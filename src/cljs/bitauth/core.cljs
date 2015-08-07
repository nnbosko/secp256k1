(ns bitauth.core
  (:require [bitpay.bitauth]))

(defn get-public-key-from-private-key
  "Generate a public key from a private key"
  ^String [^String priv-key]
  (.getPublicKeyFromPrivateKey js/BitAuth priv-key))

(defn get-sin-from-public-key
  "Generate a SIN from a compressed public key"
  ^String [^String pub-key]
  (.getSinFromPublicKey js/BitAuth pub-key))

(defn generate-sin
  "Generate a new private key, new public key, SIN and timestamp"
  []
  (-> js/BitAuth .generateSin (js->clj :keywordize-keys true)))

(defn sign
  "Sign some data with a private-key"
  ^String [^String data, ^String priv-key]
  (.sign js/BitAuth data priv-key))

(defn verify-signature
  "Verifies that a string of data has been signed."
  (^Bool [^String data, ^String pub-key, ^String hex-signature]
         (.verifySignature js/BitAuth data pub-key hex-signature))
  (^Bool [^String data, ^String pub-key, ^String hex-signature, call-back]
         (.verifySignature js/BitAuth data pub-key hex-signature call-back)))

(defn validate-sin
  "Verify that a SIN is valid"
  (^Bool [^String sin]
         (.validateSin js/BitAuth sin))
  (^Bool [^String sin, call-back]
         (.validateSin js/BitAuth sin call-back)))
