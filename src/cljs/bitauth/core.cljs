(ns bitauth.core
  "A ClojureScript implementation of BitPay's BitAuth protocol

   https://github.com/bitpay/bitauth
   http://blog.bitpay.com/2014/07/01/bitauth-for-decentralized-authentication.html"

  (:refer-clojure :exclude [even?])
  (:require [bitauth.schema :refer [Hex Base58 hex?]]
            [sjcl]
            [bitauth.formatting :refer [add-leading-zero-if-necessary
                                        DER-encode-ECDSA-signature
                                        DER-decode-ECDSA-signature]]
            [schema.core :as schema :include-macros true]
            [goog.array :refer [toArray]]
            [goog.crypt]
            [goog.crypt.Sha256]
            [goog.math.Integer]))

;;; CONSTANTS

(defonce
  ^:private
  ^:const
  ^{:doc "The secp256k1 curve object provided by SJCL that is used often"}
  curve js/sjcl.ecc.curves.k256)

(defonce
  ^:private
  ^:const
  ^{:doc "The modulus of the secp256k1 curve"}
  curve-modulus
  (new js/sjcl.bn
       "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"))

;;; UTILITY FUNCTIONS

(defn- even?
  "Patch the usual cljs.core/even? to work for sjcl.bn instances"
  [n]
  (if (instance? js/sjcl.bn n)
    (.equals (.mod n 2) 0)
    (cljs.core/even? n)))

(defn- modular-square-root
  "Compute the square root of a number modulo a prime"
  [n modulus]

  (let [modulus (new js/sjcl.bn modulus)
        n       (.mod (new js/sjcl.bn n) modulus)
        mod8    (-> modulus (.mod 8) .toString js/parseInt)]
    (assert (.greaterEquals n 2),
            "Argument must be greater than or equal to 2")
    (assert (.greaterEquals modulus 0),
            "Modulus must be non-negative")
    (cond
      ;; http://www.mersennewiki.org/index.php/Modular_Square_Root#Modulus_equal_to_2
      (.equals modulus 2)
      (.mod n modulus)

      ;; http://www.mersennewiki.org/index.php/Modular_Square_Root#Modulus_congruent_to_3_modulo_4
      (or (= mod8 3) (= mod8 7))
      (let [m (-> modulus (.add 1) .normalize .halveM .halveM)]
        (.powermod n m modulus))

      ;; http://www.mersennewiki.org/index.php/Modular_Square_Root#Modulus_congruent_to_5_modulo_8
      (= mod8 5)
      (let [m (-> modulus (.sub 5) .normalize .halveM .halveM .halveM)
            v (.powermod (.add n n) m modulus)
            i (-> (.mul v v) (.mul n) (.mul 2) (.sub 1) (.mod modulus))]
        (-> n (.mul v) (.mul i) (.mod modulus)))

      ;; http://www.mersennewiki.org/index.php/Modular_Square_Root#Modulus_congruent_to_1_modulo_8
      (= mod8 1)
      (let [q   (-> modulus (.sub 1) .normalize)
            e   (->> q
                     (iterate #(.halveM %))
                     (take-while even?)
                     count)
            two (new js/sjcl.bn 2)
            z   (->> (range) rest rest
                     (map #(new js/sjcl.bn %))
                     (map #(.powermod % q modulus))
                     (filter
                      #(not
                        (.equals
                         (.powermod % (.power two (- e 1)) modulus)
                         1)))
                     first)
            x   (.powermod n (-> q (.sub 1) .normalize .halveM) modulus)]
        (loop [y z,
               r e,
               v (-> n (.mul x) (.mod modulus)),
               w (-> n (.mul x) (.mul x) (.mod modulus))]
          (if (.equals w 1)
            v
            (let [k (->> (range)
                         (map #(vector
                                %
                                (.powermod w (.power two %) modulus)))
                         (filter #(.equals (second %) 1))
                         first first)
                  d (.powermod y (.power two (- r k 1)) modulus)
                  y (.mod (.mul d d) modulus)
                  v (.mod (.mul d v) modulus)
                  w (.mod (.mul w y) modulus)]
              (recur y k v w)))))

      :else
      (throw (ex-info "Cannot compute a square root for a non-prime modulus"
                      {:argument n,
                       :modulus modulus})))))

(defonce ^:private fifty-eight-chars-string
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

;; This has to use goog.math.Integer because we need divide
;; WARNING: I have found bugs with goog.math.Integer:
;; https://github.com/google/closure-library/issues/703
(let [fifty-eight (goog.math.Integer.fromInt 58)]
  (schema/defn ^:private hex-to-base58 :- Base58
    "Encodes a hex-string as a base58-string"
    ([input :- Hex]
     (let [leading-zeros (->> input (partition 2) (take-while #(= % '(\0 \0))) count)]
       (loop [acc [], n (goog.math.Integer.fromString input 16)]
         (if-not (.isZero n)
           (let [i (-> n (.modulo fifty-eight) .toInt)
                 s (nth fifty-eight-chars-string i)]
             (recur (cons s acc) (.divide n fifty-eight)))
           (apply str (concat
                       (repeat leading-zeros (first fifty-eight-chars-string))
                       acc))))))))

(schema/defn ^:private base58-to-hex :- Hex
  "Encodes a base58-string as a hex-string"
  [s :- Base58]
  (let [padding (->> s
                     (take-while #(= % (first fifty-eight-chars-string)))
                     (mapcat (constantly "00")))]
    (loop [result (new js/sjcl.bn 0), s s]
      (if-not (empty? s)
        (recur (.add (.mul result 58)
                     (.indexOf fifty-eight-chars-string (first s)))
               (rest s))
        (-> result
            .toBits
            js/sjcl.codec.hex.fromBits
            add-leading-zero-if-necessary
            (->> (concat padding)
                 (apply str)))))))

(defn- secure-random-bytes
  "Generate secure random bytes in a platform independent manner"
  ;; http://stackoverflow.com/a/19203948/586893
  [byte-count]
  (assert (integer? byte-count), "Argument must be an integer")
  (assert (< 0 byte-count), "Argument must greater than 0")
  (cond
    (and (exists? js/window)
         (exists? js/window.crypto)
         (exists? js/window.crypto.getRandomValues)
         (exists? js/Uint8Array))
    (->> (doto (new js/Uint8Array byte-count)
           js/window.crypto.getRandomValues)
         toArray)

    ;; IE
    (and (exists? js/window)
         (exists? js/window.msCrypto)
         (exists? js/window.msCrypto.getRandomValues)
         (exists? js/Uint8Array))
    (->> (doto (new js/Uint8Array byte-count)
           js/window.msCrypto.getRandomValues)
         toArray)

    ;; TODO: fallback to isaac.js
    ;; https://github.com/rubycon/isaac.js/blob/master/isaac.js

    :else
    (throw (ex-info "Could not securely generate random words"
                    {:byte-count byte-count}))))

(defn- secure-random
  "Generate a secure random sjcl.bn, takes a maximal value as an argument"
  [arg]
  (let [n          (new js/sjcl.bn arg)
        byte-count (-> n .bitLength (/ 8))
        bytes      (secure-random-bytes byte-count)]
    (-> bytes
        (->> (map #(add-leading-zero-if-necessary
                    (.toString % 16)))
             (apply str)
             (new js/sjcl.bn))
        (.mod n))))

;;; LIBRARY FUNCTIONS

;; TODO: Allow for uncompressed output
;; TODO: Allow for Base58 output
(schema/defn x962-point-encode :- Hex
  "Encode a sjcl.ecc.point as hex using X9.62 compression"
  [point]
  (assert (instance? js/sjcl.ecc.point point),
          "Argument is not an instance of sjcl.ecc.point")
  (let [x       (-> point .-x .toBits js/sjcl.codec.hex.fromBits)
        y-even? (-> point .-y even?)]
    (str (if y-even? "02" "03") x)))

;; Reference implementation: https://github.com/indutny/elliptic/blob/master/lib/elliptic/curve/short.js#L188
;; TODO: Support unencoded points starting with "04"
;; TODO: Support Base58 encoding, raw
(schema/defn x962-point-decode
  "Decode a sjcl.ecc.point from hex using X9.62 compression"
  [encoded-key :- Hex]
  (let [x               (-> encoded-key (subs 2) (->> (new js/sjcl.bn)))
        y-even?         (= (subs encoded-key 0 2) "02")
        ;; (x * (a + x**2) + b) % p
        y-squared       (.mod
                         (.add (.mul x (.add (.-a curve) (.mul x x))) (.-b curve))
                         curve-modulus)
        y-candidate     (modular-square-root y-squared curve-modulus)
        y               (if (= y-even? (even? y-candidate))
                          y-candidate
                          (.sub curve-modulus y-candidate))]
    (assert (.equals y-squared
                     (.mod (.mul y y) curve-modulus)),
            "Invalid point")
    (new js/sjcl.ecc.point curve x y)))

(schema/defn get-public-key-from-private-key :- Hex
  "Generate an encoded public key from a private key"
  [priv-key :- Hex]
  (->> priv-key
       (new js/sjcl.bn)
       (.mult (.-G curve))
       x962-point-encode))

(schema/defn get-sin-from-public-key :- Base58
  "Generate a SIN from a compressed public key"
  [pub-key :- Hex]
  (let [pub-prefixed (->> pub-key
                          js/sjcl.codec.hex.toBits
                          js/sjcl.hash.sha256.hash
                          js/sjcl.hash.ripemd160.hash
                          js/sjcl.codec.hex.fromBits
                          (str "0f02"))
        checksum     (->  pub-prefixed
                          js/sjcl.codec.hex.toBits
                          js/sjcl.hash.sha256.hash
                          js/sjcl.hash.sha256.hash
                          js/sjcl.codec.hex.fromBits
                          (subs 0 8))]
    (-> (str pub-prefixed checksum)
        hex-to-base58)))

(defn generate-sin
  "Generate a new private key, new public key, SIN and timestamp"
  []
  (let [priv-key (-> (secure-random (.-r curve))
                     .toBits js/sjcl.codec.hex.fromBits)
        pub-key (get-public-key-from-private-key priv-key)]
    {:created (js/Date.now),
     :priv priv-key,
     :pub pub-key,
     :sin (get-sin-from-public-key pub-key)}))

;; TODO: Optionally include recovery byte
(schema/defn sign :- Hex
  "Sign some data with a private-key"
  [priv-key-hex :- Hex, data :- schema/Str]
  (let [d    (new js/sjcl.bn priv-key-hex)
        n    (.-r curve)
        l    (.bitLength n)
        hash (js/sjcl.hash.sha256.hash data)
        z    (-> (if (> (js/sjcl.bitArray.bitLength hash) l)
                   (js/sjcl.bitArray.clamp hash l)
                   hash)
                 js/sjcl.bn.fromBits)]
    (loop []
      (let [k (.add (secure-random (.sub n 1)) 1)
            r (-> curve .-G (.mult k) .-x (.mod n))
            s (-> (.mul r d) (.add z) (.mul (.inverseMod k n)) (.mod n))]
        (cond (.equals r 0) (recur)
              (.equals s 0) (recur)
              :else
              (DER-encode-ECDSA-signature
               :R (-> r (.toBits l) js/sjcl.codec.hex.fromBits)
               :S (-> s (.toBits l) js/sjcl.codec.hex.fromBits)))))))

;; TODO: Support Base58 encoding
(schema/defn verify-signature :- schema/Bool
  "Verifies that a string of data has been signed"
  [x962-public-key data hex-signature]
  (and
   (string? data)
   (hex? x962-public-key)
   (hex? hex-signature)
   (let [pub-key    (x962-point-decode x962-public-key)
         {r-hex :R,
          s-hex :S} (DER-decode-ECDSA-signature hex-signature)
         r          (-> (new js/sjcl.bn r-hex) (.mod (.-r curve)))
         s-inv      (-> (new js/sjcl.bn s-hex)
                        (.inverseMod (.-r curve)))
         hG         (-> data
                        js/sjcl.hash.sha256.hash
                        js/sjcl.bn.fromBits
                        (.mul s-inv)
                        (.mod (.-r curve)))
         hA         (-> r (.mul s-inv) (.mod (.-r curve)))
         r2         (-> curve .-G (.mult2 hG hA pub-key) .-x (.mod (.-r curve)))]
     (.equals r r2))))

(schema/defn validate-sin :- schema/Bool
  "Verify that a SIN is valid"
  [sin]
  (try
    (and (string? sin)
         (clojure.set/subset? (set sin) (set fifty-eight-chars-string))
         (let [pub-with-checksum (base58-to-hex sin)
               len               (count pub-with-checksum)
               expected-checksum (-> pub-with-checksum (subs (- len 8) len))
               actual-checksum   (-> pub-with-checksum
                                     (subs 0 (- len 8))
                                     js/sjcl.codec.hex.toBits
                                     js/sjcl.hash.sha256.hash
                                     js/sjcl.hash.sha256.hash
                                     js/sjcl.codec.hex.fromBits
                                     (subs 0 8))]
           (and (clojure.string/starts-with? pub-with-checksum "0f02")
                (= expected-checksum actual-checksum))))
    (catch js/Object _ false)))
