(ns bitauth.schema
  "Prismatic schema for BitAuth"
  (:require [schema.core :as schema #?@(:cljs [:include-macros true])]
            [clojure.set :refer [subset?]]))

(def ^:private hex-chars (set "0123456789ABCDEFabcdef"))
(schema/defn hex? :- schema/Bool
  "Outputs if a string is hexadecimal or not"
  [x]
  (and (string? x) (subset? (set x) hex-chars)))

(def ^:private base58-chars
  (set "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"))
(schema/defn base58? :- schema/Bool
  "Outputs if a string is hexadecimal or not"
  [x]
  (and (string? x) (subset? (set x) base58-chars)))

(def Hex
  "A schema for a Hex string"
  (schema/pred hex? "HEX"))

(def Base58
  "A schema for a Base58 string"
  (schema/pred base58? "Base 58"))
