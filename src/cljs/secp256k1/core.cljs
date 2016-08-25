(ns secp256k1.core
  "A ClojureScript implementation of ECDSA signatures with secp256k1"

  (:refer-clojure :exclude [even?])
  (:require [secp256k1.formatting.der-encoding
             :refer [DER-encode-ECDSA-signature
                     DER-decode-ECDSA-signature]]
            [secp256k1.math
             :refer [modular-square-root
                     even?
                     secure-random]]
            [secp256k1.formatting.base-convert
             :refer [base-to-byte-array
                     base-to-base
                     byte-array-to-base
                     base58?
                     hex?]]
            [secp256k1.sjcl.ecc.curves :as ecc-curves]
            [secp256k1.sjcl.bn]
            [secp256k1.hashes :refer [sha256 ripemd-160]]
            [secp256k1.sjcl.bitArray :as bitArray]
            [secp256k1.sjcl.codec.bytes :as bytes]
            [secp256k1.sjcl.codec.hex :as hex])
  (:import [secp256k1.sjcl bn]
           [secp256k1.sjcl.ecc ECPoint]))

;;; CONSTANTS

(extend-protocol IEquiv
  bn
  (-equiv [a b]
    (and
      (instance? bn b)
      (.equals a b)))

  ECPoint
  (-equiv [a b]
    (and
      (instance? ECPoint b)
      (= (.-curve a) (.-curve b))
      (if (.-isIdentity a)
        (.-isIdentity b)
        (let [ax (-> a .-x)
              bx (-> b .-x)
              ay (-> a .-y)
              by (-> b .-y)]
          (and
            (every? (complement nil?) [ax bx ay by])
            (= ax bx)
            (= ay by)))))))

(defonce
  ^:private
  ^{:doc "The secp256k1 curve object provided by SJCL that is used often"}
  curve ecc-curves/k256)

(defprotocol PrivateKey
  (private-key [this] [this base]))

(extend-protocol PrivateKey

  ;; Unboxed
  bn
  (private-key
    ([priv-key _] (private-key priv-key))
    ([priv-key]
     (assert
       (.greaterEquals priv-key 1)
       "Private key should be greater than or equal to 1")
     (assert
       (.greaterEquals (.-r curve) priv-key)
       "Private key should be less than or equal to the curve modulus")
     priv-key))

  string
  (private-key
    ([this base]
     (-> this
       (base-to-base base :biginteger)
       private-key))
    ([this]
     (private-key this :hex))))

(defn- valid-point?
  "Predicate to determine if something is a valid ECC point on our curve"
  [point]
  (and
    (instance? ECPoint point)
    (= (.-curve point) curve)
    (.isValid point)))

(defprotocol PublicKey
  (public-key [this] [this base]))

(defn- x962-hex-compressed-decode
  [encoded-key]
  (let [l           (-> curve .-r .bitLength (/ 4))
        x           (-> encoded-key
                        (subs 2 (+ 2 l))
                        (->> (new bn)))
        y-even?     (= (subs encoded-key 0 2) "02")
        modulus     (-> curve .-field .-modulus)
        ;; √(x * (a + x**2) + b) % p
        y-candidate (modular-square-root
                     (.add
                      (.mul x (.add (.-a curve) (.square x)))
                      (.-b curve))
                     modulus)
        y           (if (= y-even? (even? y-candidate))
                      y-candidate
                      (.sub modulus y-candidate))]
    (public-key (new ECPoint curve x y))))

(defn- x962-hex-uncompressed-decode
  [encoded-key]
  (let [l (-> curve .-r .bitLength (/ 4))
        x (subs encoded-key 2 (+ 2 l))
        y (subs encoded-key (+ 2 l) (+ 2 (* 2 l)))]
    (public-key
     (new ECPoint curve x y))))

;; TODO: Mirror in Clojure
(defn x962-decode
  "Decode a x962-encoded public key from a hexadecimal string.

  Reference implementation: https://github.com/indutny/elliptic/blob/master/lib/elliptic/curve/short.js#L188"
  [input & {:keys [input-format]
            :or   {input-format :hex}}]
  (let [encoded-key (base-to-base input input-format :hex)
        l (-> curve .-r .bitLength (/ 4))]
    (cond
      (and (#{"02" "03"} (subs encoded-key 0 2))
           (= (+ 2 l) (count encoded-key)))
      (x962-hex-compressed-decode encoded-key)

      (and (= "04" (subs encoded-key 0 2))
           (= (+ 2 (* 2 l)) (count encoded-key)))
      (x962-hex-uncompressed-decode encoded-key)

      :else
      (throw (ex-info "Invalid encoding on public key"
                      {:encoded-key encoded-key})))))

(extend-protocol PublicKey
  ;; Unboxed
  ECPoint
  (public-key
    ([point _]
     (assert (valid-point? point) "Invalid point")
     point)
    ([point]
     (assert (valid-point? point) "Invalid point")
     point))

  array ; byte-array
  (public-key
    ([encoded-key _]
     (x962-decode encoded-key :input-format :bytes))
    ([encoded-key]
     (x962-decode encoded-key :input-format :bytes)))

  string
  (public-key
    ([encoded-key base]
     (x962-decode encoded-key :input-format base))
    ([encoded-key]
     ;; Default to hex
     (x962-decode encoded-key :input-format :hex)))

  bn
  (public-key
    ([priv-key _]
     (.mult (.-G curve) (private-key priv-key)))
    ([priv-key]
     (.mult (.-G curve) (private-key priv-key)))))

(defn x962-encode
  "Encode a sjcl.ecc.point as hex using X9.62 compression"
  [pub-key &
   {:keys [compressed output-format input-format]
    :or   {compressed    true
           input-format  :hex
           output-format :hex}}]
  (let [point (public-key pub-key input-format)
        l     (-> point .-curve .-field .-exponent)
        x     (-> point .-x (.toBits l) hex/fromBits)]
    (->
      (if compressed
        (str (if (-> point .-y even?) "02" "03") x)
        (let [y (-> point .-y .toBits hex/fromBits)]
          (str "04" x y)))
      (base-to-base :hex output-format))))

;; TODO: Switch to bitcoin addresses
(defn get-sin-from-public-key
  "Generate a SIN from a public key"
  [pub-key & {:keys [input-format output-format]
              :or   {input-format :hex
                     output-format :base58}}]
  (let [pub-prefixed (-> pub-key
                         (public-key input-format)
                         (x962-encode :output-format :bytes)
                         sha256
                         ripemd-160
                         (->> (concat [0x0F 0x02])))
        checksum     (->> pub-prefixed
                          sha256
                          sha256
                          (take 4))]
    (byte-array-to-base (concat pub-prefixed checksum) output-format)))

;; TODO: Support alternative output formats
(defn generate-sin
  "Generate a new private key, new public key, SIN and timestamp"
  []
  (let [priv-key (private-key (secure-random (.-r curve)))]
    {:created (js/Date.now),
     :priv    priv-key,
     :pub     (public-key priv-key),
     :sin     (get-sin-from-public-key priv-key)}))

;; TODO: Optionally include recovery byte, expose sign-hash
(defn sign
  "Sign some data with a private-key"
  [priv-key data]
  (let [d    (private-key priv-key)
        n    (.-r curve)
        l    (.bitLength n)
        hash (-> data sha256 bytes/toBits)
        z    (-> (if (> (bitArray/bitLength hash) l)
                   (bitArray/clamp hash l)
                   hash)
                 secp256k1.sjcl.bn/fromBits)]
    (loop []
      ;; TODO: Use RFC 6979 here
      (let [k (.add (secure-random (.sub n 1)) 1)
            r (-> curve .-G (.mult k) .-x (.mod n))
            s (-> (.mul r d) (.add z) (.mul (.inverseMod k n)) (.mod n))]
        (cond (.equals r 0) (recur)
              (.equals s 0) (recur)
              :else
              (DER-encode-ECDSA-signature
               {:R (-> r (.toBits l) hex/fromBits)
                :S (-> s (.toBits l) hex/fromBits)}))))))

;; TODO: Support alternate encodings, verify-signature-from-hash
(defn verify-signature
  "Verifies that a string of data has been signed"
  [key data hex-signature]
  (let [pub-key (public-key key)]
    (and
     (string? data)
     (hex? hex-signature)
     (try
       (let [{r :R, s :S} (DER-decode-ECDSA-signature
                           hex-signature
                           :input-format :hex
                           :output-format :biginteger)
             n          (.-r curve)
             r          (.mod r n)
             s-inv      (.inverseMod s n)
             z          (-> data
                            sha256
                            (byte-array-to-base :biginteger)
                            (.mod n))
             u1         (-> z
                            (.mul s-inv)
                            (.mod n))
             u2         (-> r (.mul s-inv) (.mod n))
             r2         (-> curve .-G
                            (.mult2 u1 u2 pub-key)
                            .-x (.mod n))]
         (= r r2))
       (catch js/Error _ false)))))

;; TODO: Switch to BitCoin Addressess
(defn validate-sin
  "Verify that a SIN is valid"
  [sin & {:keys [input-format]
          :or   {input-format :base58}}]
  (try
    (let [pub-with-checksum (base-to-byte-array sin input-format)
          len               (count pub-with-checksum)
          expected-checksum (->> pub-with-checksum (drop 22) vec)
          actual-checksum   (->> pub-with-checksum
                                 (take 22)
                                 sha256
                                 sha256
                                 (take 4)
                                 vec)
          prefix            (->> pub-with-checksum
                                 (take 2)
                                 vec)]
      (and
       (= len 26)
       (= prefix [0x0f 0x02])
       (= expected-checksum actual-checksum)))
    (catch js/Error _ false)))
