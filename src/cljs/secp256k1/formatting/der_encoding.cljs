(ns secp256k1.formatting.der-encoding
  "A (simplified) implementation of the Distinguished Encoding Rules for ECDSA signatures,
  using hexadecimal strings, and other formatting utilities.

  https://en.wikipedia.org/wiki/X.690#DER_encoding"
  (:require [secp256k1.formatting.base-convert
             :refer [hex? add-leading-zero-if-necessary]]))

(defn- encode-asn1-length
  [len]
  (->>
   (if (< len 0x80)
     [len]
     (throw (ex-info "Length is greater than or equal to 0x80, not supported"
                     {:length len})))
   (map #(.toString % 16))
   (map add-leading-zero-if-necessary)
   (apply str)))

(defn- decode-asn1-length
  [asn1]
  (let [len (-> asn1 (subs 0 2) (js/parseInt 16))]
    (when-not (zero? (bit-and len 0x80))
      (throw (ex-info "Lengths greater than 0x80 not supported"
                      {:length len
                       :asn1 asn1})))
    {:length len
     :remaining (subs asn1 2)}))

(defn- format-asn1-unsigned-integer
  "Formats a hexadecimal encoding an unsigned integer, dropping left zeros and padding with a left zero if necessary to avoid being confused for a two's complement"
  [n]
  (let [bytes (->> n
                   (partition 2)
                   (map (partial apply str))
                   (map #(js/parseInt % 16))
                   (drop-while zero?))]
    (->> (if-not (zero? (bit-and (first bytes) 0x80))
           (conj bytes 0)
           bytes)
         (map #(add-leading-zero-if-necessary (.toString % 16)))
         (apply str))))

(defn encode-asn1-unsigned-integer
  "Formats a hexadecimal as an unsigned integer, padding and prepending a length"
  [n]
  (if (hex? n)
    (let [formatted-n (format-asn1-unsigned-integer n)
          len         (-> formatted-n count (/ 2)
                          encode-asn1-length)]
      (str "02" len formatted-n))
    (throw (ex-info "Cannot encode argument" {:argument n}))))

(defn decode-asn1-integer
  "Decodes an int from the top of an ASN.1 encoded string"
  [asn1]
  (assert (= (subs asn1 0 2) "02"), "ASN.1 must have a 02 tag for an integer")
  (let [{:keys [length remaining]} (decode-asn1-length (subs asn1 2))]
    {:integer (subs remaining 0 (* 2 length))
     :remaining (subs remaining (* 2 length))}))

(defn DER-decode
  "Decodes a list of hexadecimal numbers from a string following the distinguished encoding rules"
  [asn1]
  (assert (hex? asn1), "Input must be hex")
  (assert (= "30" (subs asn1 0 2)), "Input must start with the code 30")
  (let [{:keys [:length :remaining]} (decode-asn1-length (subs asn1 2))]
    (when-not (= (* length 2) (count remaining))
      (throw (ex-info "Decoded header length does not match actual length of message"
                      {:decoded-header-length (* 2 length)
                       :actual-length        (count remaining)
                       :message              remaining
                       :full-asn1            asn1})))
    (loop [ret [], remaining remaining]
      (if (empty? remaining)
        ret
        (let [{:keys [:integer :remaining]} (decode-asn1-integer remaining)]
          (recur (conj ret integer) remaining))))))

(defn DER-encode
  "Formats a list of hexadecimal numbers using the distinguished encoding rules"
  [n]
  (->> n
       (map encode-asn1-unsigned-integer)
       (apply str)
       encode-asn1-unsigned-integer
       (#(subs % 2))
       (str "30")))


(defn DER-encode-ECDSA-signature
  "Formats an ECDSA signature"
  [&{:keys [:R :S :recover]}]
  (assert (hex? R), "R argument must be hex")
  (assert (not (empty? R)), "R argument must not be empty")
  (assert (hex? S), "S argument must be hex")
  (assert (not (empty? S)), "S argument must not be empty")
  (cond
    (empty? recover) (DER-encode [R S])
    (hex? recover) (DER-encode [R S recover])
    :else (throw (ex-info "Cannot encode message"
                          {:R R
                           :S S
                           :recover recover}))))

(defn DER-decode-ECDSA-signature
  "Formats an ECDSA signature"
  [ecdsa]
  (assert (hex? ecdsa), "Argument must be hex")
  (assert (not (empty? ecdsa)), "Argument must not be empty")
  (let [[R S recover] (DER-decode ecdsa)]
    {:R R
     :S S
     :recover recover}))
