(ns secp256k1.spec
 (:refer-clojure :exclude [assert])
 (:require
  secp256k1.data
  [clojure.spec.alpha :as spec])
 #?(:cljs
    (:import
     [secp256k1.sjcl.ecc ECPoint])))

#?(:clj
   (defn valid-point?
    "Determine if an Secp256k1 point is valid"
    [point]
    (and (instance? org.bouncycastle.math.ec.ECPoint point)
         (let [x       (-> point .getXCoord .toBigInteger)
               y       (-> point .getYCoord .toBigInteger)
               ecc     (.getCurve secp256k1.data/curve)
               a       (-> ecc .getA .toBigInteger)
               b       (-> ecc .getB .toBigInteger)
               p       (-> ecc .getField .getCharacteristic)]
           (= (mod (+ (* x x x) (* a x) b) p)
              (mod (* y y) p)))))

   :cljs
   (defn valid-point?
     "Predicate to determine if something is a valid ECC point on our curve"
     [point]
     (and
       (instance? ECPoint point)
       (= (.-curve point) secp256k1.data/curve)
       (.isValid point))))

(spec/def :secp256k1/public-key valid-point?)

(spec/def :secp256k1/private-key
 (spec/and
  java.math.BigInteger
  #?(:clj
     #(<= 1 %)
     :cljs
     #(.greaterEquals % 1))
  #?(:clj
     #(<= % (.getN secp256k1.data/curve))
     :cljs
     #(.greaterEquals (.-r secp256k1.data/curve) %))))

(defn assert
 [s v]
 (clojure.core/assert
  (spec/valid? s v)
  (spec/explain-str s v)))
