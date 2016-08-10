(ns secp256k1.core
  "A Clojure implementation of BitPay's BitAuth protocol

  https://github.com/bitpay/secp256k1
  http://blog.bitpay.com/2014/07/01/secp256k1-for-decentralized-authentication.html"

  (:require [clojure.string :refer [starts-with?]]
            [secp256k1.schema :refer [hex?]]
            [secp256k1.hashes :refer [sha256 ripemd-160]]
            [clojure.set])
  (:import java.io.ByteArrayOutputStream
           java.security.SecureRandom
           javax.xml.bind.DatatypeConverter
           org.spongycastle.asn1.ASN1InputStream
           org.spongycastle.asn1.ASN1Integer
           org.spongycastle.asn1.DERSequenceGenerator
           org.spongycastle.asn1.sec.SECNamedCurves
           org.spongycastle.crypto.generators.ECKeyPairGenerator
           org.spongycastle.crypto.params.ECDomainParameters
           org.spongycastle.crypto.params.ECKeyGenerationParameters
           org.spongycastle.crypto.params.ECPrivateKeyParameters
           org.spongycastle.crypto.params.ECPublicKeyParameters
           org.spongycastle.crypto.signers.ECDSASigner))

(defonce
  ^:private
  ^{:doc "The secp256k1 curve object provided by SpongyCastle that is used often"}
  curve
  (let [params (SECNamedCurves/getByName "secp256k1")]
    (ECDomainParameters. (.getCurve params)
                         (.getG params)
                         (.getN params)
                         (.getH params))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; TODO: Write public-key validation function

(defprotocol PrivateKey
  (private-key [this] [this base]))

;; TODO: Fix Clojure upstream because this class breaks extend-protocol
(extend-type (Class/forName "[B")
  PrivateKey
  (private-key [data]
    (private-key (BigInteger. 1 data))))

;; A lone java.math.BigInteger is an unboxed private key
(extend-protocol PrivateKey
  java.math.BigInteger
  (private-key
    [this]
    ;; TODO: Validate
    this)

  clojure.lang.BigInt
  (private-key
    [this] (-> this .toBigInteger private-key))

  java.lang.String
  (private-key
    ([this]
     (private-key this :hex))
    ;; TODO: Handle base conversion
    ([encoded-key base]
     (-> encoded-key
         DatatypeConverter/parseHexBinary
         private-key))))

(defprotocol PublicKey
  (public-key [this] [this base]))

(extend-type (Class/forName "[B")
  PublicKey
  (public-key
    [data]
    (-> curve
        .getCurve
        (.decodePoint data))))

(extend-protocol PublicKey
  org.spongycastle.math.ec.ECPoint
  (public-key
    [this]
    ;; TODO: Validate
    (.normalize this))

  java.lang.String
  (public-key
    ([encoded-key]
     (public-key encoded-key :hex))
    ;; TODO: handle base conversion
    ([encoded-key base]
     (-> encoded-key
         DatatypeConverter/parseHexBinary
         public-key)))

  java.math.BigInteger
  (public-key
    [this]
    (-> curve
        .getG
        (.multiply this)
        .normalize))

  clojure.lang.BigInt
  (public-key
    [this]
    (public-key (private-key this))))

(defn x962-encode
  "Encode a public key as hex using X9.62 compression"
  [pub-key & {:keys [compressed]
              :or   {compressed true}}]
  (let [point (public-key pub-key)
        x (-> point .getXCoord .toBigInteger)
        y (-> point .getYCoord .toBigInteger)]
    (-> curve
        .getCurve
        (.createPoint x y compressed)
        .getEncoded
        DatatypeConverter/printHexBinary
        .toLowerCase)))

(defn get-public-key-from-private-key
  "Generate a public key from a private key"
  [priv-key & {:keys [compressed]
               :or {compressed true}}]
  (-> priv-key
      private-key
      public-key
      (x962-encode :compressed compressed)))

(defonce ^:private ^:const fifty-eight-chars-string
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

(defn- hex-to-base58
  "Encodes a hex-string as a base58-string"
  [input]
  (let [leading-zeros (->> input (partition 2) (take-while #(= % '(\0 \0))) count)]
    (loop [acc [], n (BigInteger. input 16)]
      (if (pos? n)
        (let [i (rem n 58)
              s (nth fifty-eight-chars-string i)]
          (recur (cons s acc) (quot n 58)))
        (apply str (concat
                    (repeat leading-zeros (first fifty-eight-chars-string))
                    acc))))))

(defn get-sin-from-public-key
  "Generate a SIN from a compressed public key"
  [pub-key]
  (let [pub-prefixed (->> pub-key
                          DatatypeConverter/parseHexBinary
                          sha256
                          ripemd-160
                          DatatypeConverter/printHexBinary .toLowerCase
                          (str "0f02"))
        checksum     (-> pub-prefixed
                         DatatypeConverter/parseHexBinary
                         sha256
                         sha256
                         DatatypeConverter/printHexBinary .toLowerCase
                         (subs 0 8))]
    (-> (str pub-prefixed checksum)
        hex-to-base58)))

(defn generate-sin
  "Generate a new private key, new public key, SIN and timestamp"
  []
  (let [priv-key
        (-> (ECKeyPairGenerator.)
            (doto (.init (ECKeyGenerationParameters. curve (SecureRandom.))))
            .generateKeyPair
            .getPrivate .getD (.toString 16))
        pub-key (get-public-key-from-private-key priv-key)]
    {:created (System/currentTimeMillis),
     :priv priv-key,
     :pub pub-key,
     :sin (get-sin-from-public-key pub-key)}))

(defn sign
  "Sign some data with a private-key"
  [priv-key data]
  (let [input (-> data (.getBytes "UTF-8") sha256)
        spongy-priv-key (-> priv-key
                            (BigInteger. 16)
                            (ECPrivateKeyParameters. curve))
        sigs (-> (ECDSASigner.)
                 (doto (.init true spongy-priv-key))
                 (.generateSignature input))
        bos (ByteArrayOutputStream.)]
    (with-open [s (DERSequenceGenerator. bos)]
      (doto s
        (.addObject (ASN1Integer. (get sigs 0)))
        (.addObject (ASN1Integer. (get sigs 1)))))
    (-> bos .toByteArray DatatypeConverter/printHexBinary .toLowerCase)))

(defn- verify
  "Verifies the given ASN.1 encoded ECDSA signature against a hash (byte-array) using a specified public key."
  [pub-key, input, hex-signature]
  (let [spongy-pub-key (-> pub-key
                           public-key
                           (ECPublicKeyParameters. curve))
        signature (DatatypeConverter/parseHexBinary hex-signature)
        verifier (doto (ECDSASigner.) (.init false spongy-pub-key))]
    (with-open [decoder (ASN1InputStream. signature)]
      (let [sequence (.readObject decoder)
            r (-> sequence (.getObjectAt 0) .getValue)
            s (-> sequence (.getObjectAt 1) .getValue)]
        (.verifySignature verifier input r s)))))

(defn verify-signature
  "Verifies that a string of data has been signed"
  [pub-key data hex-signature]
  (and
   (string? data)
   (hex? pub-key)
   (hex? hex-signature)
   (try
     (verify pub-key  (-> data (.getBytes "UTF-8") sha256) hex-signature)
     (catch Exception _ false))))

(defn-
  base58-to-hex
  "Encodes a base58-string as a hex-string"
  [s]
  (let [padding (->> s
                     (take-while #(= % (first fifty-eight-chars-string)))
                     (map (constantly (byte 0))))]
    (loop [result 0, s s]
      (if-not (empty? s)
        (recur (+ (*' result 58)
                  (.indexOf fifty-eight-chars-string (str (first s))))
               (rest s))
        (->> result
             str
             java.math.BigInteger.
             .toByteArray
             (drop-while zero?)
             (concat padding)
             byte-array
             DatatypeConverter/printHexBinary .toLowerCase)))))

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
                                     DatatypeConverter/parseHexBinary
                                     sha256
                                     sha256
                                     DatatypeConverter/printHexBinary .toLowerCase
                                     (subs 0 8))]
           (and (clojure.string/starts-with? pub-with-checksum "0f02")
                (= expected-checksum actual-checksum))))
    (catch Exception _ false)))
