(ns secp256k1.core
  "ECDSA secp256k1 signatures in Clojure."

  (:require [clojure.string :refer [starts-with?]]
            [secp256k1.hashes :refer [sha256 ripemd-160]]
            [secp256k1.formatting.base-convert
             :refer [byte-array-to-base
                     base-to-byte-array
                     base-to-base
                     base58?
                     hex?]]
            [clojure.set])
  (:import java.io.ByteArrayOutputStream
           java.security.SecureRandom
           org.bouncycastle.asn1.ASN1InputStream
           org.bouncycastle.asn1.ASN1Integer
           org.bouncycastle.asn1.DERSequenceGenerator
           org.bouncycastle.asn1.sec.SECNamedCurves
           org.bouncycastle.crypto.generators.ECKeyPairGenerator
           org.bouncycastle.crypto.params.ECDomainParameters
           org.bouncycastle.crypto.params.ECKeyGenerationParameters
           org.bouncycastle.crypto.params.ECPrivateKeyParameters
           org.bouncycastle.crypto.params.ECPublicKeyParameters
           org.bouncycastle.crypto.signers.ECDSASigner))

(defonce
  ^:private
  ^{:doc "The secp256k1 curve object provided by BouncyCastle that is used often"}
  curve
  (let [params (SECNamedCurves/getByName "secp256k1")]
    (ECDomainParameters. (.getCurve params)
                         (.getG params)
                         (.getN params)
                         (.getH params))))

(defprotocol PrivateKey
  (private-key [this] [this base]))

(extend-protocol PrivateKey
  (Class/forName "[B")
  (private-key
    ([data _]
     (private-key data))
    ([data]
     (private-key (BigInteger. 1 data))))

  java.math.BigInteger ; Unboxed
  (private-key
    ([priv-key _] (private-key priv-key))
    ([priv-key]
     (assert (<= 1 priv-key) "Private key should be at least 1")
     (assert (<= priv-key (.getN curve))
             "Private key should be less than curve modulus")
     priv-key))

  clojure.lang.BigInt
  (private-key
    [priv-key] (-> priv-key .toBigInteger private-key))

  java.lang.String
  (private-key
    ([priv-key]
     (private-key priv-key :hex))
    ([encoded-key base]
     (-> encoded-key
         (base-to-byte-array base)
         private-key))))

(defn- valid-point?
  "Determine if an Secp256k1 point is valid"
  [point]
  (and (instance? org.bouncycastle.math.ec.ECPoint point)
       (let [x       (-> point .getXCoord .toBigInteger)
             y       (-> point .getYCoord .toBigInteger)
             ecc     (.getCurve curve)
             a       (-> ecc .getA .toBigInteger)
             b       (-> ecc .getB .toBigInteger)
             p       (-> ecc .getField .getCharacteristic)]
         (= (mod (+ (* x x x) (* a x) b) p)
            (mod (* y y) p)))))

(defprotocol PublicKey
  (public-key [this] [this base]))

(extend-protocol PublicKey
  (Class/forName "[B")
  (public-key
    ([data _] (public-key data))
    ([data] (public-key (.decodePoint (.getCurve curve) data))))

  org.bouncycastle.math.ec.ECPoint ; Unboxed
  (public-key
    ([this _] (public-key this))
    ([this]
     (let [point (.normalize this)]
       (assert (valid-point? point) "Invalid Point")
       point)))

  java.lang.String
  (public-key
    ([encoded-key] (public-key encoded-key :hex))
    ([encoded-key base]
     (public-key (base-to-byte-array encoded-key base))))

  java.math.BigInteger
  (public-key
    ([this _] (public-key this))
    ([this] (-> curve
                .getG
                (.multiply (private-key this))
                .normalize)))

  clojure.lang.BigInt
  (public-key
    ([this _] (public-key this))
    ([this] (public-key (private-key this)))))

;; TODO: Test input and output formats
(defn x962-encode
  "Encode a public key as hex using X9.62 compression"
  [pub-key & {:keys [compressed output-format input-format]
              :or   {compressed true
                     input-format :hex
                     output-format :hex}}]
  (let [point (public-key pub-key input-format)
        x (-> point .getXCoord .toBigInteger)
        y (-> point .getYCoord .toBigInteger)]
    (-> curve
        .getCurve
        (.createPoint x y compressed)
        .normalize
        .getEncoded
        (byte-array-to-base output-format))))

;; TODO: Switch this to make BitCoin addresses
(defn get-sin-from-public-key
  "Generate a SIN from a public key"
  [pub-key & {:keys [output-format]
              :or   {output-format :base58}}]
  (let [pub-prefixed (-> pub-key
                         (x962-encode :output-format :bytes)
                         sha256
                         ripemd-160
                         (->> (concat [0x0F 0x02])))
        checksum     (->> pub-prefixed
                          sha256
                          sha256
                          (take 4))]
    (byte-array-to-base (concat pub-prefixed checksum) output-format)))

(defn generate-sin
  "Generate a new private key, new public key, SIN and timestamp"
  []
  (let [priv-key
        (-> (ECKeyPairGenerator.)
            (doto (.init
                   (ECKeyGenerationParameters.
                    curve
                    (SecureRandom.))))
            .generateKeyPair
            .getPrivate .getD
            private-key)
        pub-key (public-key priv-key)]
    {:created (System/currentTimeMillis),
     :priv priv-key,
     :pub pub-key,
     :sin (get-sin-from-public-key pub-key)}))

(defn sign
  "Sign some data with a private-key"
  [priv-key data]
  (let [input (-> data (.getBytes "UTF-8") sha256)
        bouncy-priv-key (-> priv-key
                            private-key
                            (ECPrivateKeyParameters. curve))
        sigs (-> (ECDSASigner.)
                 (doto (.init true bouncy-priv-key))
                 (.generateSignature input))
        bos (ByteArrayOutputStream.)]
    (with-open [s (DERSequenceGenerator. bos)]
      (doto s
        (.addObject (ASN1Integer. (get sigs 0)))
        (.addObject (ASN1Integer. (get sigs 1)))))
    (-> bos
        .toByteArray
        (byte-array-to-base :hex))))

;; TODO: key, data, and hex signature need formats
(defn- verify
  "Verifies the given ASN.1 encoded ECDSA signature against a hash (byte-array) using a specified public key."
  [key, input, hex-signature]
  (let [bouncy-pub-key (-> key
                           public-key
                           (ECPublicKeyParameters. curve))
        signature (base-to-byte-array hex-signature :hex)
        verifier (doto (ECDSASigner.) (.init false bouncy-pub-key))]
    (with-open [decoder (ASN1InputStream. signature)]
      (let [sequence (.readObject decoder)
            r (-> sequence (.getObjectAt 0) .getValue)
            s (-> sequence (.getObjectAt 1) .getValue)]
        (.verifySignature verifier input r s)))))

;; TODO: key, data, and hex signature need formats
(defn verify-signature
  "Verifies that a string of data has been signed"
  [key data hex-signature]
  (and
   (string? data)
   (satisfies? PublicKey key)
   (hex? hex-signature)
   (try
     (verify key (sha256 data) hex-signature)
     (catch Exception _ false))))


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
    (catch Throwable _ false)))
