(ns bitauth.core
  "A ClojureScript implementation of BitPay's BitAuth protocol

  https://github.com/bitpay/bitauth
  http://blog.bitpay.com/2014/07/01/bitauth-for-decentralized-authentication.html"

  (:require [bitauth.schema :refer [Hex Base58]]
            [com.bitpay.BitAuth]
            [schema.core :as schema :include-macros true]))

(schema/defn get-public-key-from-private-key :- Hex
  "Generate a public key from a private key"
  [priv-key :- Hex]
  (.getPublicKeyFromPrivateKey js/bitauth priv-key))

(schema/defn get-sin-from-public-key :- Base58
  "Generate a SIN from a compressed public key"
  [pub-key :- Hex]
  (.getSinFromPublicKey js/bitauth pub-key))

(defn generate-sin
  "Generate a new private key, new public key, SIN and timestamp"
  []
  (-> js/bitauth .generateSin (js->clj :keywordize-keys true)))

(schema/defn sign :- Hex
  "Sign some data with a private-key"
  [data :- schema/Str, priv-key :- Hex]
  (.sign js/bitauth data priv-key))

(schema/defn verify-signature :- schema/Bool
  "Verifies that a string of data has been signed."
  ([data :- schema/Str, pub-key :- Hex, hex-signature :- Hex]
   (.verifySignature js/bitauth data pub-key hex-signature))
  ([data :- schema/Str, pub-key :- Hex, hex-signature :- Hex, call-back]
   (.verifySignature js/bitauth data pub-key hex-signature call-back)))

(schema/defn validate-sin :- schema/Bool
  "Verify that a SIN is valid"
  ([sin :- Base58]
   (.validateSin js/bitauth sin))
  ([sin :- Base58, call-back]
   (.validateSin js/bitauth sin call-back)))
