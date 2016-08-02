(ns bitauth.core
  "A Clojure implementation of BitPay's BitAuth protocol

  https://github.com/bitpay/bitauth
  http://blog.bitpay.com/2014/07/01/bitauth-for-decentralized-authentication.html"

  (:require [clojure.string :refer [starts-with?]]
            [bitauth.schema :refer [hex?]]
            [bitauth.hashes :refer [sha256 ripemd-160]]
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

(defn- zero-pad-left
  "Pad a hex string with zeros on the left until it is the specified length"
  [s, n ]
  (if (< (count s) n)
    (apply str (concat (repeat (- n (count s)) \0) s))
    s))

(declare x962-point-encode)
(declare x962-point-decode)

(defn x962-point-encode
  "Encode a public key as hex using X9.62 compression"
  [pub-key & {:keys [compressed]
              :or {compressed true}}]
  (cond
    (instance? org.spongycastle.math.ec.ECPoint$Fp pub-key)
    (if compressed
      (let [x (-> pub-key
                  .normalize
                  .getXCoord
                  .toBigInteger
                  (.toString 16)
                  (zero-pad-left 64))
            y-even? (-> pub-key
                        .normalize
                        .getYCoord
                        .toBigInteger
                        even?)]
        (str (if y-even? "02" "03") x))
      (let [x (-> pub-key
                  .normalize
                  .getXCoord
                  .toBigInteger
                  (.toString 16)
                  (zero-pad-left 64))
            y (-> pub-key
                  .normalize
                  .getYCoord
                  .toBigInteger
                  (.toString 16)
                  (zero-pad-left 64))]
        (str "04" x y)))

    (and
     (hex? pub-key)
     (#{"02" "03"} (subs pub-key 0 2)))
    (let [pt (x962-point-decode pub-key)]
      (assert (= (x962-point-encode pt) pub-key), "Invalid point")
      (if compressed
        pub-key
        (x962-point-encode pt :compressed false)))

    (and
     (hex? pub-key)
     (= "04" (subs pub-key 0 2)))
    (let [pt (x962-point-decode pub-key)]
      (assert (= (x962-point-encode pt :compressed false) pub-key),
              "Invalid point")
      (if-not compressed
        pub-key
        (x962-point-encode pt)))

    :else
    (throw (ex-info "Cannot encode argument"
                    {:argument pub-key
                     :compressed compressed}))))

(defn x962-point-decode
  "Decode a public key using X9.62 compression"
  [encoded-key]
  (cond
    (instance? org.spongycastle.math.ec.ECPoint$Fp encoded-key)
    (do
      (assert
       (let [hex-key (x962-point-encode encoded-key :compressed false)]
         (= (x962-point-decode hex-key) encoded-key)), "Invalid point")
      encoded-key)

    (hex? encoded-key)
    (->> encoded-key
         DatatypeConverter/parseHexBinary
         (.decodePoint (.getCurve curve))
         .normalize)

    :else
    (throw (ex-info "Cannot decode argument" {:argument encoded-key}))))

(defn get-public-key-from-private-key
  "Generate a public key from a private key"
  [priv-key & {:keys [compressed]
               :or {compressed true}}]
  (-> curve
      .getG
      (.multiply (BigInteger. priv-key 16))
      .normalize
      (x962-point-encode :compressed compressed)))

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
            .getPrivate .getD (.toString 16) (zero-pad-left 64))
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
                           x962-point-decode
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
