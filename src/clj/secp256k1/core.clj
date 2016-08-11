(ns secp256k1.core
  "ECDSA secp256k1 signatures in Clojure."

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

(defprotocol PrivateKey
  (private-key [this] [this base]))

(extend-protocol PrivateKey
  (Class/forName "[B")
  (private-key [data]
    (private-key (BigInteger. 1 data)))

  java.math.BigInteger ; Unboxed
  (private-key
    [priv-key]
    (assert (<= 1 priv-key) "Private key should be at least 1")
    (assert (<= priv-key (.getN curve))
            "Private key should be less than curve modulus")
    priv-key)

  clojure.lang.BigInt
  (private-key
    [priv-key] (-> priv-key .toBigInteger private-key))

  java.lang.String
  (private-key
    ([priv-key]
     (private-key priv-key :hex))
    ;; TODO: Handle base conversion
    ([encoded-key base]
     (-> encoded-key
         DatatypeConverter/parseHexBinary
         private-key))))

(defn- valid-point?
  "Determine if an Secp256k1 point is valid"
  [point]
  (and (instance? org.spongycastle.math.ec.ECPoint point)
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
    [data]
    (public-key (.decodePoint (.getCurve curve) data)))

  org.spongycastle.math.ec.ECPoint ; Unboxed
  (public-key
    [this]
    (let [point (.normalize this)]
      (assert (valid-point? point) "Invalid Point")
      point))

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
        (.multiply (private-key this))
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
        .normalize
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
  "Generate a SIN from a public key"
  [pub-key]
  (let [pub-prefixed (->> pub-key
                          x962-encode
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
    (hex-to-base58 (str pub-prefixed checksum))))

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
     :pub (public-key priv-key),
     :sin (get-sin-from-public-key pub-key)}))

(defn sign
  "Sign some data with a private-key"
  [priv-key data]
  (let [input (-> data (.getBytes "UTF-8") sha256)
        spongy-priv-key (-> priv-key
                            private-key
                            (ECPrivateKeyParameters. curve))
        sigs (-> (ECDSASigner.)
                 (doto (.init true spongy-priv-key))
                 (.generateSignature input))
        bos (ByteArrayOutputStream.)]
    (with-open [s (DERSequenceGenerator. bos)]
      (doto s
        (.addObject (ASN1Integer. (get sigs 0)))
        (.addObject (ASN1Integer. (get sigs 1)))))
    (-> bos
        .toByteArray
        DatatypeConverter/printHexBinary
        .toLowerCase)))

(defn- verify
  "Verifies the given ASN.1 encoded ECDSA signature against a hash (byte-array) using a specified public key."
  [key, input, hex-signature]
  (let [spongy-pub-key (-> key
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
  [key data hex-signature]
  (and
   (string? data)
   (satisfies? PublicKey key)
   (hex? hex-signature)
   (try
     (verify key (sha256 data) hex-signature)
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
