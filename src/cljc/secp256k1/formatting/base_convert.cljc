(ns secp256k1.formatting.base-convert
  "Utilities for doing base conversions"
  (:require [clojure.set :refer [subset?]]
            [clojure.string :refer [lower-case]]
    #?@(:cljs [[goog.crypt]
               [secp256k1.sjcl.bn :as bn]
               [goog.crypt.base64]
               [goog.math.Integer :as Integer]]))
  #?(:clj (:import javax.xml.bind.DatatypeConverter)))

;; Implementation notes:
;;
;; While byte-arrays are first class in Clojure,
;; sadly hex-arrays are first class in ClojureScript
;;
;; Rationale:
;;
;; The Google Closure library sometimes deals in byte arrays
;;    - For instance, in goog.crypt.base64, goog.crypt/byteArrayToHex,
;;      and goog.crypt/hexTobytearray
;;
;; However goog.math.Integer deals in arrays of signed words, and currently
;; has broken multiplication.
;;    - For instance, goog.math.Integer/fromBits
;;
;; Similarly, sjcl only deals in arrays of signed words

(let [hex-chars-set (set "0123456789ABCDEFabcdef")]
  (defn hex?
    "Outputs if a string is hexadecimal or not"
    [x]
    (and (string? x) (subset? (set x) hex-chars-set))))

(def ^:private base-fifty-eight-chars
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

(let [base58-chars-set (set base-fifty-eight-chars)]
  (defn base58?
    "Outputs if a string is hexadecimal or not"
    [x]
    (and (string? x) (subset? (set x) base58-chars-set))))

(defn add-leading-zero-if-necessary
  "Adds a leading zero to a hex string if it is of odd length"
  [s]
  (assert (hex? s) "Argument must be a hexadecimal string")
  (if (odd? (count s)) (str "0" s) s))

#?(:clj
   (defn-
     base58-to-byte-array
     "Encodes a base58-string as a byte-array"
     [s]
     (assert (base58? s) "Input must be in base 58")
     (let [padding (->> s
                     (take-while
                       #(= % (first base-fifty-eight-chars)))
                     (map (constantly 0)))]
       (loop [result 0, s s]
         (if-not (empty? s)
           (recur (+ (*' result 58)
                    (.indexOf base-fifty-eight-chars (str (first s))))
             (rest s))
           (->> result
             .toBigInteger
             .toByteArray
             (drop-while zero?)
             (concat padding)
             byte-array)))))
   :cljs
   (defn base58-to-hex
     "Encodes a base 58 string as a hexadecimal string"
     [s]
     (assert (base58? s) "Input must be in base 58")
     (let [padding (->> s
                     (take-while #(= % (first base-fifty-eight-chars)))
                     (mapcat (constantly "00")))]
       (loop [result bn/ZERO,
              s s]
         (if-not (empty? s)
           (recur (.add (.mul result 58)
                    (.indexOf base-fifty-eight-chars (first s)))
             (rest s))
           (-> result
             .toString
             (subs 2)                                       ; Strip leading 0x from Hex representation of result
             add-leading-zero-if-necessary
             (->> (concat padding)
               (apply str))))))))

#?(:cljs
   (defn bytes? [x]
     "Predicate to determine that whether something is an unsigned sequence of bytes"
     (and (or (implements? ISeqable x) (array? x))
       (every? int? x)
       (every? #(and (<= 0 %) (<= % 255))
         (map #(unsigned-bit-shift-right % 0) x)))))

(defn base-to-byte-array
  "Convert a string of specified base to a byte-array"
  [data format]
  (case format
    :hex #?(:clj  (DatatypeConverter/parseHexBinary data)
            :cljs (do
                    (assert (hex? data) "Input must be in hexadecimal")
                    (goog.crypt/hexToByteArray data)))
    :base64 #?(:clj  (DatatypeConverter/parseBase64Binary data)
               :cljs (goog.crypt.base64/decodeStringToByteArray data))
    :base58 #?(:clj  (base58-to-byte-array data)
               :cljs (-> data
                       base58-to-hex
                       goog.crypt/hexToByteArray))
    :bytes #?(:clj  (byte-array data)
              :cljs (do (assert (bytes? data)
                          "Argument must be a byte array")
                        (clj->js data)))
    (throw (ex-info "Unsupported format"
             {:data   data
              :format format}))))

#?(:clj
   (defn- byte-array-to-base58
     "Encodes a byte array as a base 58 string"
     [data]
     (let [leading-zeros
           (->> data (take-while zero?) count)]
       (loop [acc [], n (BigInteger. 1 data)]
         (if (pos? n)
           (let [i (rem n 58)
                 s (nth base-fifty-eight-chars i)]
             (recur (cons s acc) (quot n 58)))
           (apply str (concat
                        (repeat leading-zeros
                          (first base-fifty-eight-chars))
                        acc))))))
   :cljs
   (let [fifty-eight (Integer/fromInt 58)]
     (defn hex-to-base58
       "Encodes a hexadecimal string as a base 58 string"
       [input]
       (assert (hex? input) "Input must be in hexadecimal")
       (let [leading-zeros (->> input (partition 2) (take-while #(= % '(\0 \0))) count)]
         (loop [acc [],
                n   (Integer/fromString input 16)]
           (if-not (.isZero n)
             (let [i (-> n (.modulo fifty-eight) .toInt)
                   s (nth base-fifty-eight-chars i)]
               (recur (cons s acc) (.divide n fifty-eight)))
             (apply str (concat
                          (repeat leading-zeros (first base-fifty-eight-chars))
                          acc))))))))

(defn byte-array-to-base
  [data output-format]
  #?(:cljs (assert (bytes? data) "Data must be a sequence of unsigned bytes"))
  (let [data #?(:clj (byte-array data)
                :cljs (clj->js data))]
    (case output-format
      :hex #?(:clj  (-> data
                      DatatypeConverter/printHexBinary
                      lower-case)
              :cljs (goog.crypt/byteArrayToHex data))
      :base64 #?(:clj  (DatatypeConverter/printBase64Binary data)
                 :cljs (goog.crypt.base64/encodeByteArray data))
      :base58 #?(:clj  (byte-array-to-base58 data)
                 :cljs (-> data
                         goog.crypt/byteArrayToHex
                         hex-to-base58))
      :bytes data
      (throw (ex-info "Unsupported output-format"
               {:data          data
                :output-format output-format})))))

#?(:clj
   (defn hex-to-base58
     "Encodes a hex-string as a base58-string"
     [data]
     (assert (hex? data) "Input must be hexadecimal")
     (-> data
       DatatypeConverter/parseHexBinary
       byte-array-to-base58)))

#?(:clj
   (defn base58-to-hex
     "Encodes a base58-string as a hex-string"
     [data]
     (assert (base58? data) "Input must be in base58")
     (-> data
       base58-to-byte-array
       (byte-array-to-base :hex))))

(defn base-to-base
  "Convert one base into another"
  [data input-format output-format]
  (cond
    (nil? data)
    data

    (= input-format output-format)
    data

    (= [:base58 :hex]
      [input-format output-format])
    (base58-to-hex data)

    (= [:hex :base58]
      [input-format output-format])
    (hex-to-base58 data)

    :else
    (-> data
      (base-to-byte-array input-format)
      (byte-array-to-base output-format))))
