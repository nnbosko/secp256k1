(ns bitauth.java-interop
  (:require [bitauth.core :refer [get-public-key-from-private-key
                                  get-sin-from-public-key
                                  generate-sin
                                  sign
                                  verify-signature
                                  validate-sin]])
  (:import com.bitpay.SIN)
  (:gen-class
   :name "com.bitpay.bitauth"
   :methods [^:static
             [getPublicKeyFromPrivateKey [String] String]
             [getSinFromPublicKey [String] String]
             [sign [String, String] String]
             [generateSin [] SIN]
             [verifySignature [String, String, String] Boolean]
             [validateSin [String] Boolean]]))

(defn -getPublicKeyFromPrivateKey
  "Generate a public key from a private key (Java Interface)"
  ^String [^String priv-key]
  (get-public-key-from-private-key priv-key))

(defn -getSinFromPublicKey
  "Generate a SIN from a compressed public key"
  ^String [^String pub-key])

(defn -generateSin
  "Generate a new private key, new public key, SIN and timestamp"
  ^SIN []
  (let [{:keys [priv pub sin created]} (generate-sin)]
    (SIN. priv pub sin created)))

(defn -sign
  "Sign some data with a private-key"
  ^String [^String data, ^String priv-key]
  (sign data priv-key))

(defn -verifySignature
  "Verifies that a string of data has been signed."
  ^Boolean [^String data, ^String pub-key, ^String hex-signature]
  (verify-signature data pub-key hex-signature))

(defn -validateSin
  ^Boolean [^String sin]
  (validate-sin sin))
