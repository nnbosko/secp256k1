(ns bitauth.core
  (:require [cljsjs.bitauth]))

(defn get-public-key-from-private-key
  "Generate a public key from a private key"
  ^String [^String priv-key]
  (.getPublicKeyFromPrivateKey js/bitauth priv-key))

(defn get-sin-from-public-key
  "Generate a SIN from a compressed public key"
  ^String [^String pub-key]
  (.getSinFromPublicKey js/bitauth pub-key))

(defn generate-sin
  "Generate a new private key, new public key, SIN and timestamp"
  []
  (-> js/bitauth .generateSin (js->clj :keywordize-keys true)))

(defn sign
  "Sign some data with a private-key"
  ^String [^String data, ^String priv-key]
  (.sign js/bitauth data priv-key))

(defn verify-signature
  "Verifies that a string of data has been signed."
  (^Boolean [^String data, ^String pub-key, ^String hex-signature]
            (.verifySignature js/bitauth data pub-key hex-signature))
  (^Boolean [^String data, ^String pub-key, ^String hex-signature, call-back]
            (.verifySignature js/bitauth data pub-key hex-signature call-back)))

(defn validate-sin
  "Verify that a SIN is valid"
  (^Boolean [^String sin]
            (.validateSin js/bitauth sin))
  (^Boolean [^String sin, call-back]
            (.validateSin js/bitauth sin call-back)))
