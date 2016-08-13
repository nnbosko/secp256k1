(ns secp256k1.core
  "A ClojureScript implementation of BitPay's BitAuth protocol

   https://github.com/bitpay/secp256k1
   http://blog.bitpay.com/2014/07/01/secp256k1-for-decentralized-authentication.html"

  (:refer-clojure :exclude [even?])
  (:require [sjcl]
            [secp256k1.formatting.der-encoding
             :refer [
                     DER-encode-ECDSA-signature
                     DER-decode-ECDSA-signature]]
            [secp256k1.math
             :refer [modular-square-root
                     even?
                     secure-random]]
            [secp256k1.formatting.base-convert
             :refer [array-to-base
                     add-leading-zero-if-necessary
                     base58?
                     base-to-array
                     hex?]]
            [goog.math.Integer :as Integer]))

;;; CONSTANTS

(defonce
  ^:private
  ^{:doc "The secp256k1 curve object provided by SJCL that is used often"}
  curve js/sjcl.ecc.curves.k256)

;; Move to some library for bases
;;; UTILITY FUNCTIONS

(defonce ^:private fifty-eight-chars-string
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

(let [fifty-eight (Integer/fromInt 58)]
  (defn- hex-to-base58
    "Encodes a hex-string as a base58-string"
    [input]
    (let [leading-zeros (->> input (partition 2) (take-while #(= % '(\0 \0))) count)]
      (loop [acc [],
             n (Integer/fromString input 16)]
        (if-not (.isZero n)
          (let [i (-> n (.modulo fifty-eight) .toInt)
                s (nth fifty-eight-chars-string i)]
            (recur (cons s acc) (.divide n fifty-eight)))
          (apply str (concat
                      (repeat leading-zeros (first fifty-eight-chars-string))
                      acc)))))))

(defn- base58-to-hex
  "Encodes a base58-string as a hex-string"
  [s]
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

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(extend-protocol IEquiv
  js/sjcl.bn
  (-equiv [a b]
    (and
     (instance? js/sjcl.bn b)
     (.equals a b)))

  js/sjcl.ecc.point
  (-equiv [a b]
    (and
     (instance? js/sjcl.ecc.point b)
     (let [ax (.-x a)
           bx (.-x b)
           ay (.-y a)
           by (.-y b)]
       (and (= ax bx)
            (= ay by))))))

(defprotocol PrivateKey
  (private-key [this] [this base]))

(extend-protocol PrivateKey

  js/sjcl.bn ; Unboxed
  (private-key
    ([priv-key _] (private-key priv-key))
    ([priv-key]
     (assert
      (= (.greaterEquals priv-key 1) 1)
      "Private key should be greater than or equal to 1")
     (assert
      (= (.greaterEquals (.-r curve) priv-key) 1)
      "Private key should be less than or equal to the curve modulus")
     priv-key))

  string
  (private-key
    ([this base]
     (-> this
         (base-to-array base)
         (array-to-base base)
         (->> (new js/sjcl.bn))
         private-key))
    ([this]
     (private-key this :hex))))

(defn- valid-point?
  "Predicate to determine if something is a valid ECC point on our curve"
  [point]
  (and (instance? js/sjcl.ecc.point point)
       (let [x (.-x point)
             y (.-y point)
             a (.-a curve)
             b (.-b curve)
             modulus (-> curve .-field .-modulus)]
         (and
          (instance? js/sjcl.bn x)
          (instance? js/sjcl.bn y)
          (= (.mod (.add (.mul x (.add a (.square x))) b) modulus)
             (.mod (.square y) modulus))))))

(defprotocol PublicKey
  (public-key [this] [this base]))

(extend-protocol PublicKey
  js/sjcl.ecc.point ; Unboxed
  (public-key [point]
    (assert (valid-point? point) "Invalid point")
    point)

  string
  (public-key
    ;; TODO: Use base here
    ([encoded-key base]
     ;; Reference implementation: https://github.com/indutny/elliptic/blob/master/lib/elliptic/curve/short.js#L188
     (cond
       (and (#{"02" "03"} (subs encoded-key 0 2))
            (= 66 (count encoded-key)))
       (let [x           (-> encoded-key
                             (subs 2 66)
                             (->> (new js/sjcl.bn)))
             y-even?     (= (subs encoded-key 0 2) "02")
             modulus     (-> curve .-field .-modulus)
             ;; √(x * (a + x**2) + b) % p
             y-candidate (modular-square-root
                          (.add
                           (.mul x (.add (.-a curve) (.square x)))
                           (.-b curve))
                          modulus)
             y          (if (= y-even? (even? y-candidate))
                          y-candidate
                          (.sub modulus y-candidate))]
         (public-key
          (new js/sjcl.ecc.point curve x y)))

       (= "04" (subs encoded-key 0 2))
       (let [x (-> encoded-key (subs 2 66) (->> (new js/sjcl.bn)))
             y (-> encoded-key (subs 66) (->> (new js/sjcl.bn)))]
         (public-key
          (new js/sjcl.ecc.point curve x y)))

       :else
       (throw (ex-info "Cannot handle encoded public key"
                       {:encoded-key encoded-key}))))

    ([this]
     (assert (hex? this) "Argument must be hexadecimal")
     (public-key this :hex)))

  js/sjcl.bn
  (public-key [priv-key]
    (.mult (.-G curve) (private-key priv-key))))

;; TODO: Allow for Base58/Base64
(defn x962-encode
  "Encode a sjcl.ecc.point as hex using X9.62 compression"
  [pub-key & {:keys [compressed]
              :or   {compressed true}}]
  (let [point (public-key pub-key)
        x     (-> point .-x .toBits js/sjcl.codec.hex.fromBits)]
    (if compressed
      (str (if (-> point .-y even?) "02" "03") x)
      (let [y (-> point .-y .toBits js/sjcl.codec.hex.fromBits)]
        (str "04" x y)))))

(defn get-sin-from-public-key
  "Generate a SIN from a compressed public key"
  [pub-key & {:keys [output-format]
              :or   {output-format :base58}}]
  (let [pub-prefixed (->> pub-key
                          x962-encode
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
  (let [priv-key (private-key (secure-random (.-r curve)))]
    {:created (js/Date.now),
     :priv    priv-key,
     :pub     (public-key priv-key),
     :sin     (get-sin-from-public-key priv-key)}))

;; TODO: Optionally include recovery byte
(defn sign
  "Sign some data with a private-key"
  [priv-key data]
  (let [d    (private-key priv-key)
        n    (.-r curve)
        l    (.bitLength n)
        hash (js/sjcl.hash.sha256.hash data)
        z    (-> (if (> (js/sjcl.bitArray.bitLength hash) l)
                   (js/sjcl.bitArray.clamp hash l)
                   hash)
                 js/sjcl.bn.fromBits)]
    (loop []
      ;; TODO: Use RFC 6979 here
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
(defn verify-signature
  "Verifies that a string of data has been signed"
  [key data hex-signature]
  (and
   (string? data)
   (satisfies? PublicKey key)
   (hex? hex-signature)
   (try
     (let [{r-hex :R,
            s-hex :S} (DER-decode-ECDSA-signature hex-signature)
           pub-key    (if (instance? js/sjcl.ecc.point key)
                        key
                        (public-key key))
           n          (.-r curve)
           r          (-> (new js/sjcl.bn r-hex) (.mod n))
           s-inv      (-> (new js/sjcl.bn s-hex) (.inverseMod n))
           z          (-> data
                          js/sjcl.hash.sha256.hash
                          js/sjcl.bn.fromBits
                          (.mod n))
           u1         (-> z
                          (.mul s-inv)
                          (.mod n))
           u2         (-> r (.mul s-inv) (.mod n))
           r2         (-> curve .-G
                          (.mult2 u1 u2 pub-key)
                          .-x (.mod n))]
       (= r r2))
     (catch js/Error _ false))))

(defn validate-sin
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
    (catch js/Error _ false)))
