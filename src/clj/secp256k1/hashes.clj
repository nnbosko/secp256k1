(ns secp256k1.hashes
  "Hashing utilities used for elliptic curve cryptography"

  (:import
   java.security.MessageDigest
   org.spongycastle.crypto.digests.RIPEMD160Digest
   org.spongycastle.crypto.digests.SHA256Digest
   org.spongycastle.crypto.macs.HMac
   org.spongycastle.crypto.params.KeyParameter
   org.spongycastle.crypto.signers.ECDSASigner))

(defprotocol ByteSerializable
  (to-bytes [this]))

(extend-protocol ByteSerializable
  (Class/forName "[B") (to-bytes [ba] ba)
  String (to-bytes [s] (.getBytes s "UTF-8"))
  clojure.lang.Sequential (to-bytes [ba] (byte-array ba)))

(defn sha256
  "Get the SHA256 hash of a byte-array"
  [data]
  (-> (MessageDigest/getInstance "SHA-256")
      (.digest (to-bytes data))))

;; Use spongycastle/bouncycastle because javax.crypto.Mac doesn't support empty keys
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
  "Get the ripemd-160 hash of a hex string"
  [data]
  (let [data (to-bytes data)
        d (doto (RIPEMD160Digest.) (.update data 0 (count data)))
        o (byte-array (.getDigestSize d))]
    (.doFinal d o 0)
    o))
