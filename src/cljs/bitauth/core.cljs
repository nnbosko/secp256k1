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
            [bitauth.math :refer [modular-square-root even? secure-random]]
            [schema.core :as schema :include-macros true]
            [goog.array :refer [toArray]]
            [goog.crypt]
            [goog.crypt.Sha256]
            [goog.math.Integer]))

;;; CONSTANTS

(defonce
  ^:private
  ^{:doc "The secp256k1 curve object provided by SJCL that is used often"}
  curve js/sjcl.ecc.curves.k256)

(defonce
  ^:private
  ^{:doc "The modulus of the secp256k1 curve"}
  curve-modulus
  (new js/sjcl.bn
       "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"))

;;; UTILITY FUNCTIONS

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

;;; LIBRARY FUNCTIONS
;; Reference implementation: https://github.com/indutny/elliptic/blob/master/lib/elliptic/curve/short.js#L188
(declare x962-point-encode)
(declare x962-point-decode)

;; TODO: Support Base58 encoding, raw
(defn x962-point-decode
  "Decode a sjcl.ecc.point from hex using X9.62 compression"
  [encoded-key]
  (cond
    (instance? js/sjcl.ecc.point encoded-key)
    ;; TODO: Check the key is valid
    encoded-key

    (contains? #{"02" "03"} (subs encoded-key 0 2))
    (let [x           (-> encoded-key (subs 2) (->> (new js/sjcl.bn)))
          y-even?     (= (subs encoded-key 0 2) "02")
          ;; (x * (a + x**2) + b) % p
          y-squared   (.mod
                       (.add (.mul x (.add (.-a curve) (.mul x x))) (.-b curve))
                       curve-modulus)
          y-candidate (modular-square-root y-squared curve-modulus)
          y           (if (= y-even? (even? y-candidate))
                        y-candidate
                        (.sub curve-modulus y-candidate))]
      (assert (.equals y-squared
                       (.mod (.mul y y) curve-modulus)),
              "Invalid point")
      (new js/sjcl.ecc.point curve x y))

    (= "04" (subs encoded-key 0 2))
    (let [x (-> encoded-key (subs 2 66) (->> (new js/sjcl.bn)))
          y (-> encoded-key (subs 66 130) (->> (new js/sjcl.bn)))]
      (assert (.equals
               (.mod
                (.add (.mul x (.add (.-a curve) (.mul x x))) (.-b curve))
                curve-modulus)
               (.mod (.mul y y) curve-modulus)),
              "Invalid point")
      (new js/sjcl.ecc.point curve x y))

    :else
    (throw (ex-info "Cannot handle encoded public key"
                    {:encoded-key encoded-key}))))

;; TODO: Allow for Base58 output
(defn x962-point-encode
  "Encode a sjcl.ecc.point as hex using X9.62 compression"
  [point & {:keys [:compressed]
            :or   {:compressed true}}]
  (cond
    (instance? js/sjcl.ecc.point point)
    (if compressed
      (let [x       (-> point .-x .toBits js/sjcl.codec.hex.fromBits)
            y-even? (-> point .-y even?)]
        (str (if y-even? "02" "03") x))
      (let [x (-> point .-x .toBits js/sjcl.codec.hex.fromBits)
            y (-> point .-y .toBits js/sjcl.codec.hex.fromBits)]
        (str "04" x y)))

    (and (hex? point) (contains? #{"02" "03"} (subs point 0 2)))
    (let [pt (x962-point-decode point)]
      (assert (= (x962-point-encode pt) point), "Invalid point")
      (if compressed
        point
        (x962-point-encode pt :compressed false)))

    (and
     (hex? point)
     (= "04" (subs point 0 2)))
    (let [pt (x962-point-decode point)]
      (assert (= (x962-point-encode pt :compressed false) point),
              "Invalid point")
      (if-not compressed
        point
        (x962-point-encode pt :compressed true)))

    :else
    (throw (ex-info "Cannot handle argument" {:argument point
                                              :compressed compressed}))))

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
   (try
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
       (.equals r r2))
     (catch :default _ false))))

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
