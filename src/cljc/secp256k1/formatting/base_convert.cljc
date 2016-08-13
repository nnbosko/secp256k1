(ns secp256k1.formatting.base-convert
  (:require [clojure.set :refer [subset?]]
            [clojure.string :refer [lower-case]]
            #?@(:cljs [[goog.crypt]
                       [goog.crypt.base64]
                       [goog.math.Integer :as Integer]]))
  #?(:clj (:import javax.xml.bind.DatatypeConverter)))

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

#?(:cljs
   (defn base58-to-hex
     "Encodes a base58-string as a hex-string"
     [s]
     (let [padding (->> s
                        (take-while #(= % (first base-fifty-eight-chars)))
                        (mapcat (constantly "00")))]
       (loop [result (new js/sjcl.bn 0), s s]
         (if-not (empty? s)
           (recur (.add (.mul result 58)
                        (.indexOf base-fifty-eight-chars (first s)))
                  (rest s))
           (-> result
               .toBits
               js/sjcl.codec.hex.fromBits
               add-leading-zero-if-necessary
               (->> (concat padding) (apply str))))))))

#?(:clj
   (defn-
     base58-to-array
     "Encodes a base58-string as a byte-array"
     [s]
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
   (defn- base58-to-array
     "Encodes a base58-string as a byte-array"
     [s]
     (-> s
         base58-to-array
         goog.crypt/hexToByteArray)))

(defn base-to-array
  [data base]
  (case base
    :hex   #?(:clj  (DatatypeConverter/parseHexBinary data)
              :cljs (goog.crypt/hexToByteArray data))
    :base58 (base58-to-array data)
    (throw (ex-info "Unsupported base"
                    {:data data
                     :base base}))))

#?(:clj
   (defn- array-to-base58
     "Encodes a byte array as a base58-string"
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
     (defn- array-to-base58
       "Encodes a byte-array as a base58-string"
       [input]
       (let [leading-zeros (->> input (take-while zero?) count)]
         (loop [acc [],
                n
                (-> input
                    goog.crypt/byteArrayToHex
                    (Integer/fromString 16))]
           (if-not (.isZero n)
             (let [i (-> n (.modulo fifty-eight) .toInt)
                   s (nth base-fifty-eight-chars i)]
               (recur (cons s acc) (.divide n fifty-eight)))
             (apply str (concat
                         (repeat leading-zeros
                                 (first base-fifty-eight-chars))
                         acc))))))))

#?(:cljs
   (defn bytes? [x]
     "Predicate to determine that whether something is an unsigned sequence of bytes"
     (and (or (implements? ISeqable x) (array? x))
          (every? int? x)
          (every? (partial <= 0) x)
          (every? (partial >= 255) x))))

(defn array-to-base
  [data output-format]
  #?(:cljs (assert (bytes? data)
                    "Data must be a sequence of unsigned bytes"))
  (let [data #?(:clj (byte-array data)
                :cljs (clj->js data))]
    (case output-format
      :hex    #?(:clj (-> data
                          DatatypeConverter/printHexBinary
                          lower-case)
                 :cljs (goog.crypt/byteArrayToHex data))
      :base64 #?(:clj (DatatypeConverter/printBase64Binary data)
                 :cljs (goog.crypt.base64/encodeByteArray data))
      :base58 (array-to-base58 data)
      :bytes  data
      (throw (ex-info "Unsupported output-format"
                      {:data          data
                       :output-format output-format})))))
