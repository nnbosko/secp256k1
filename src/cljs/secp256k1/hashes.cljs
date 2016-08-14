(ns secp256k1.hashes
  (:require [goog.crypt]
            [secp256k1.formatting.base-convert :refer [bytes?]]
            )
  (:import [goog.crypt Sha256]))

(defprotocol ByteSerializable
  "Serialize data into a JavaScript array of bytes"
  (to-bytes [this]))

(extend-protocol ByteSerializable
  array (to-bytes [a]
         (assert (bytes? a) "Input must be an array of bytes")
          a)
  string (to-bytes [s] (goog.crypt.stringToUtf8ByteArray s))
  default (to-bytes [x]
            (if (bytes? x)
              (clj->js x)
              (throw (ex-info "Cannot convert argument to byte array"
                              {:argument x})))))

(defn sha256
  "Get the SHA256 hash and return a byte-array"
  [& data]
  (let [d (new Sha256)]
    (doseq [datum data]
      (.update d (to-bytes datum)))
    (.digest d)))
