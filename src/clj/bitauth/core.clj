(ns bitauth.core
  "A Clojure implementation of BitPay's BitAuth protocol

  https://github.com/bitpay/bitauth
  http://blog.bitpay.com/2014/07/01/bitauth-for-decentralized-authentication.html"

  (:require [bitauth.schema :refer [Hex Base58 hex?]]
            [schema.core :as schema]
            [clojure.string :refer [starts-with?]]
            [clojure.set])
  (:import java.io.ByteArrayOutputStream
           java.security.MessageDigest
           java.security.SecureRandom
           java.util.Arrays
           org.spongycastle.asn1.ASN1InputStream
           org.spongycastle.asn1.DERInteger
           org.spongycastle.asn1.DERSequenceGenerator
           org.spongycastle.asn1.sec.SECNamedCurves
           org.spongycastle.crypto.digests.RIPEMD160Digest
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

(defn- strip-0x
  "Gets rid of the leading `0x` identifier of hex strings"
  [s]
  (if (starts-with? (.toLowerCase s) "0x") (.substring s 2) s))

(defn- add-leading-zero-if-necessary
  "Adds a leading zero to a hex string if it is of odd length"
  [s]
  (if (odd? (count s)) (str "0" s) s))

(defn- hex-char-to-byte
  "Convert a single hexdecimal character to a byte"
  [c]
  (-> c (Character/digit 16) byte))

(schema/defn ^:private hex-to-array
  "Convert a string to a byte array, discarding leading zeros as necessary"
  [s :- Hex]
  (->> s
       strip-0x
       add-leading-zero-if-necessary
       (partition 2)
       (map
        (fn [[a b]]
          (+ (bit-shift-left (hex-char-to-byte a) 4)
             (hex-char-to-byte b))))
       byte-array))

(defonce ^:private ^:const hex-chars-string "0123456789abcdef")

(schema/defn ^:private array-to-hex :- Hex
  "Encode a collection of bytes as hex"
  [b]
  (apply str (for [x    b
                   :let [v (bit-and x 0xFF)]
                   y    [(get hex-chars-string (bit-shift-right v 4))
                         (get hex-chars-string (bit-and v 0x0F))]]
               y)))

(defn- sha256
  "Get the SHA256 hash of a byte-array"
  [data]
  (-> (MessageDigest/getInstance "SHA-256")
      (.digest data)))

(defn- ripemd-160
  "Get the ripemd-160 hash of a hex string"
  [a]
  (let [d (doto (RIPEMD160Digest.) (.update a 0 (count a)))
        o (byte-array (.getDigestSize d))]
    (.doFinal d o 0)
    o))

(schema/defn ^:private zero-pad-left :- Hex
  "Pad a hex string with zeros on the left until it is the specified length"
  [s :- Hex, n :- schema/Int]
  (if (< (count s) n)
    (apply str (concat (repeat (- n (count s)) \0) s))
    s))

(declare x962-point-encode)
(declare x962-point-decode)

(defn x962-point-encode
  "Encode a public key as hex using X9.62 compression"
  [pub-key & {:keys [:compressed]
              :or {:compressed true}}]
  (cond
    (instance? org.spongycastle.math.ec.ECPoint$Fp pub-key)
    (if compressed
      (let [x (-> pub-key .getX .toBigInteger (.toString 16) (zero-pad-left 64))
            y-even? (-> pub-key .getY .toBigInteger even?)]
        (str (if y-even? "02" "03") x))
      (let [x (-> pub-key .getX .toBigInteger (.toString 16) (zero-pad-left 64))
            y (-> pub-key .getY .toBigInteger (.toString 16) (zero-pad-left 64))]
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
         hex-to-array
         (.decodePoint (.getCurve curve)))

    :else
    (throw (ex-info "Cannot decode argument" {:argument encoded-key}))))

(schema/defn get-public-key-from-private-key :- Hex
  "Generate a public key from a private key"
  [priv-key :- Hex]
  (-> curve
      .getG
      (.multiply (BigInteger. priv-key 16))
      x962-point-encode))

(defonce ^:private ^:const fifty-eight-chars-string
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

(schema/defn ^:private
  hex-to-base58 :- Base58
  "Encodes a hex-string as a base58-string"
  [input :- Hex]
  (let [leading-zeros (->> input (partition 2) (take-while #(= % '(\0 \0))) count)]
    (loop [acc [], n (BigInteger. input 16)]
      (if (pos? n)
        (let [i (rem n 58)
              s (nth fifty-eight-chars-string i)]
          (recur (cons s acc) (quot n 58)))
        (apply str (concat
                    (repeat leading-zeros (first fifty-eight-chars-string))
                    acc))))))

(schema/defn get-sin-from-public-key :- Base58
  "Generate a SIN from a compressed public key"
  [pub-key :- Hex]
  (let [pub-prefixed (->> pub-key
                          hex-to-array
                          sha256
                          ripemd-160
                          array-to-hex
                          (str "0f02"))
        checksum     (-> pub-prefixed
                         hex-to-array
                         sha256
                         sha256
                         array-to-hex
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

(schema/defn sign :- Hex
  "Sign some data with a private-key"
  [priv-key :- Hex, data :- String]
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
        (.addObject (DERInteger. (get sigs 0)))
        (.addObject (DERInteger. (get sigs 1)))))
    (-> bos .toByteArray array-to-hex)))

(schema/defn ^:private verify :- Boolean
  "Verifies the given ASN.1 encoded ECDSA signature against a hash (byte-array) using a specified public key."
  [pub-key :- Hex, input, hex-signature :- Hex]
  (let [spongy-pub-key (-> pub-key
                           x962-point-decode
                           (ECPublicKeyParameters. curve))
        signature (hex-to-array hex-signature)
        verifier (doto (ECDSASigner.) (.init false spongy-pub-key))]
    (with-open [decoder (ASN1InputStream. signature)]
      (let [sequence (.readObject decoder)
            r (-> sequence (.getObjectAt 0) .getValue)
            s (-> sequence (.getObjectAt 1) .getValue)]
        (.verifySignature verifier input r s)))))

(schema/defn verify-signature :- Boolean
  "Verifies that a string of data has been signed"
  [pub-key data hex-signature]
  (and
   (string? data)
   (hex? pub-key)
   (hex? hex-signature)
   (try
     (verify pub-key  (-> data (.getBytes "UTF-8") sha256) hex-signature)
     (catch Exception _ false))))

(schema/defn ^:private
  base58-to-hex :- Hex
  "Encodes a base58-string as a hex-string"
  [s :- Base58]
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
             array-to-hex)))))

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
                                     hex-to-array
                                     sha256
                                     sha256
                                     array-to-hex
                                     (subs 0 8))]
           (and (clojure.string/starts-with? pub-with-checksum "0f02")
                (= expected-checksum actual-checksum))))
    (catch Exception _ false)))

(comment (run-tests))
