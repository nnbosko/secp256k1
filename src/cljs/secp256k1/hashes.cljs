(ns secp256k1.hashes
  (:require [goog.crypt])
  (:import [goog.crypt Sha256]))

(defprotocol ByteSerializable
  (to-bytes [this]))

(extend-protocol ByteSerializable
  array
  (to-bytes [a]
    (assert (every? int? a) "All array values must be integers")
    (assert (every? pos? a) "All array values must be positive")
    (assert (every? (partial >= 0xFF) a)
            "All array values must be less than or equal to 0xFF")
    a)

  string
  (to-bytes [s]
    (goog.crypt/stringToUtf8ByteArray s)))

(defn sha256 [data]
  (-> (Sha256.)
      (doto (.update (to-bytes data)))
      .digest))
