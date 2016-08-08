(ns secp256k1.schema
  "Prismatic schema for BitAuth"
  (:require [clojure.set :refer [subset?]]))

(def ^:private hex-chars (set "0123456789ABCDEFabcdef"))
(defn hex?
  "Outputs if a string is hexadecimal or not"
  [x]
  (and (string? x) (subset? (set x) hex-chars)))

(def ^:private base58-chars
  (set "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"))

(defn base58?
  "Outputs if a string is hexadecimal or not"
  [x]
  (and (string? x) (subset? (set x) base58-chars)))
