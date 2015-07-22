(ns bitauth.core
  "An implementation of BitPay's BitAuth protocol

  https://github.com/bitpay/bitauth
  http://blog.bitpay.com/2014/07/01/bitauth-for-decentralized-authentication.html"

  (:require [base58.core :refer [int-to-base58] :as base58])
  (:import java.io.ByteArrayOutputStream
           java.security.MessageDigest
           java.security.SecureRandom
           java.util.Arrays
           org.bouncycastle.asn1.ASN1InputStream
           org.bouncycastle.asn1.DERInteger
           org.bouncycastle.asn1.DERSequenceGenerator
           org.bouncycastle.asn1.sec.SECNamedCurves
           org.bouncycastle.crypto.digests.RIPEMD160Digest
           org.bouncycastle.crypto.generators.ECKeyPairGenerator
           org.bouncycastle.crypto.params.ECDomainParameters
           org.bouncycastle.crypto.params.ECKeyGenerationParameters
           org.bouncycastle.crypto.params.ECPrivateKeyParameters
           org.bouncycastle.crypto.params.ECPublicKeyParameters
           org.bouncycastle.crypto.signers.ECDSASigner
           org.bouncycastle.util.encoders.Hex))

;; The secp256k1 curve object provided by BouncyCastle and used by almost everything
(defonce ^:private curve
  (let [params (SECNamedCurves/getByName "secp256k1")]
    (ECDomainParameters. (.getCurve params)
                         (.getG params)
                         (.getN params)
                         (.getH params))))

(defn- hex-to-array
  "Convert a string to a byte array, discarding leading zeros as necessary"
  [^String s]
  (let [a (-> s (BigInteger. 16) .toByteArray)]
    (if (and (-> (count a) (> 32))
             ;; TODO: This is a clumsy way of getting rid of zeros,
             ;; there should be a flag or something
             (every? zero? (Arrays/copyOfRange a 0 (- (count a) 32))))
      (Arrays/copyOfRange a (- (count a) 32) (count a))
      a)))

(defn- array-to-hex
  "Encode an collection of bytes as hex"
  ^String [b]
  (let [chars "0123456789abcdef"]
    (-> (for [x b :let [v (bit-and x 0xFF)]]
          [(get chars (bit-shift-right v 4))
           (get chars (bit-and v 0x0F))])
        flatten
        char-array
        String.)))

(defn- hex-sha256
  "Get the SHA256 hash of a hex string"
  ^String [^String s]
  (-> (MessageDigest/getInstance "SHA-256")
      (.digest (hex-to-array s))
      Hex/encode
      String.))

(defn- sha256
  "Get the SHA256 hash of a string"
  ^String [^String s]
  (-> (MessageDigest/getInstance "SHA-256")
      (.digest (.getBytes s))
      Hex/encode
      String.))

(defn- ripemd-160-hex
  "Get the ripemd-160-hex hash of a hex string"
  ^String [^String s]
  (let [a (hex-to-array s)
        d (doto (RIPEMD160Digest.) (.update a 0 (count a)))
        o (byte-array (.getDigestSize d))]
    (.doFinal d o 0)
    (-> o Hex/encode String.)))

(defn- x962-point-encode
  "Encode a public key as hex using X9.62 compression"
  ^String [pub-key]
  (let [x (-> pub-key .getX .toBigInteger (.toString 16))
        y-even? (-> pub-key .getY .toBigInteger even?)]
    (str (if y-even? "02" "03") x)))

(defn- x962-point-decode
  "Decode a public key using X9.62 compression"
  [^String encoded-key]
  (->> encoded-key
       hex-to-array
       (.decodePoint (.getCurve curve))))

(defn get-public-key-from-private-key
  "Generate a public key from a private key"
  ^String [^String priv-key]
  (-> curve
      .getG
      (.multiply (BigInteger. priv-key 16))
      x962-point-encode))

(defn get-sin-from-public-key
  "Generate a SIN from a compressed public key"
  ^String [^String pub-key]
  (let [pub-hash (hex-sha256 pub-key)
        pub-prefixed (str "0f02" (ripemd-160-hex pub-hash))
        checksum (-> pub-prefixed hex-sha256 hex-sha256 (subs 0 8))]
    (int-to-base58
     (BigInteger. (str pub-prefixed checksum) 16) 0)))

(defn generate-sin
  "Generate a new private key, new public key, SIN and timestamp"
  []
  (let [key-pair
        (-> (ECKeyPairGenerator.)
            (doto (.init (ECKeyGenerationParameters. curve (SecureRandom.))))
            .generateKeyPair)
        priv (-> key-pair .getPrivate .getD (.toString 16))
        pub (get-public-key-from-private-key priv)]
    {:created (-> (System/currentTimeMillis) (/ 1000)),
     :priv priv,
     :pub pub,
     :sin (get-sin-from-public-key pub)}))

(defn sign
  "Sign some data with a private-key"
  ^String [^String data, ^String priv-key]
  (let [input (-> data sha256 hex-to-array)
        bouncy-priv-key (-> priv-key
                            (BigInteger. 16)
                            (ECPrivateKeyParameters. curve))
        sigs (->
              (ECDSASigner.)
              (doto (.init true bouncy-priv-key))
              (.generateSignature input))
        bos (ByteArrayOutputStream.)]
    (with-open [s (DERSequenceGenerator. bos)]
      (doto s
        (.addObject (DERInteger. (get sigs 0)))
        (.addObject (DERInteger. (get sigs 1)))))
    (-> bos .toByteArray array-to-hex)))

(defn verify
  "Verifies the given ASN.1 encoded ECDSA signature against a hash (byte-array) using a specified public key."
  [input pub-key hex-signature]
  (let [bouncy-pub-key (-> pub-key
                           x962-point-decode
                           (ECPublicKeyParameters. curve))
        signature (hex-to-array hex-signature)
        verifier (doto (ECDSASigner.) (.init false bouncy-pub-key))]
    (with-open [decoder (ASN1InputStream. signature)]
      (let [sequence (.readObject decoder)
            r (-> sequence (.getObjectAt 0) .getValue)
            s (-> sequence (.getObjectAt 1) .getValue)]
        (.verifySignature verifier input r s)))))

(defn verify-signature
  "Verifies that a string of data has been signed."
  [data pub-key hex-signature]
  (verify (-> data sha256 hex-to-array) pub-key hex-signature))

(defn validate-sin
  "Verify that a SIN is valid"
  [sin]
  (let [pub-with-checksum (-> sin base58/decode array-to-hex)
        len (count pub-with-checksum)
        expected-checksum (-> pub-with-checksum (subs (- len 8) len))
        actual-checksum (-> pub-with-checksum
                            (subs 0 (- len 8))
                            hex-sha256
                            hex-sha256
                            (subs 0 8))]
    (= expected-checksum actual-checksum)))
