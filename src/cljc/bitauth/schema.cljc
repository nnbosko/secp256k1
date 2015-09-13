(ns bitauth.schema
  "Prismatic schema for BitAuth"
  (:require [schema.core :as schema #?@(:cljs [:include-macros true])]))

(schema/defn ^:private hex-string? :- schema/Bool
  "Outputs if a string is hexadecimal or not"
  [x :- schema/Str]
  (->> x (re-matches #"[0-9a-fA-F]*") nil? not))

(schema/defn ^:private base58-string? :- schema/Bool
  "Outputs if a string is hexadecimal or not"
  [x :- schema/Str]
  (->> x (re-matches #"[1-9A-Za-z]*") nil? not))

(def Hex
  "A schema for a Hex string"
  (schema/pred hex-string?))

(def Base58
  "A schema for a Base58 string"
  (schema/pred base58-string?))
