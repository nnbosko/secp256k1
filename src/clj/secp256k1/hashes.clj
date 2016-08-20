(ns secp256k1.hashes
  "Hashing utilities used for elliptic curve cryptography"

  (:import
   java.security.MessageDigest
   org.bouncycastle.crypto.digests.RIPEMD160Digest
   org.bouncycastle.crypto.digests.SHA256Digest
   org.bouncycastle.crypto.macs.HMac
   org.bouncycastle.crypto.params.KeyParameter
   org.bouncycastle.crypto.signers.ECDSASigner))

(defprotocol ByteSerializable
  "Serialize data into a byte array"
  (to-bytes [this]))

(extend-protocol ByteSerializable
  (Class/forName "[B") (to-bytes [ba] ba)
  String (to-bytes [s] (.getBytes s "UTF-8"))
  clojure.lang.Sequential (to-bytes [ba] (byte-array ba)))

(defn sha256
  "Get the SHA256 hash and return a byte-array"
  [& data]
  (let [d (MessageDigest/getInstance "SHA-256")]
    (doseq [datum data]
      (.update d (to-bytes datum)))
    (.digest d)))

;; Use spongycastle/bouncycastle because javax.crypto.Mac
;; doesn't support empty keys (one of the standard test vectors)
(defn hmac-sha256
  "Compute the HMAC given a private key and data using SHA256"
  [k data]
  (let [data (to-bytes data)
        hmac (doto (HMac. (SHA256Digest.))
               (.init (KeyParameter. (to-bytes k)))
               (.update data 0 (count data)))
        o (byte-array (.getMacSize hmac))]
    (.doFinal hmac o 0)
    o))

(defn ripemd-160
  "Get the ripemd-160 hash"
  [& data]
  (let [d (RIPEMD160Digest.)
        o (byte-array (.getDigestSize d))]
    (doseq [datum data]
      (let [datum (to-bytes datum)]
        (.update d datum 0 (count datum))))
    (let [o (byte-array (.getDigestSize d))]
      (.doFinal d o 0)
      o)))
