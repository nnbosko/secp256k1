(ns secp256k1.data
 #?(:cljs
    (:require
     [secp256k1.sjcl.ecc.curves :as ecc-curves]))
 #?(:clj
    (:import
     org.bouncycastle.asn1.sec.SECNamedCurves
     org.bouncycastle.crypto.params.ECDomainParameters)))

#?(:clj
   (defonce
    ^{:doc "The secp256k1 curve object provided by BouncyCastle that is used often"}
    curve
    (let [params (SECNamedCurves/getByName "secp256k1")]
     (ECDomainParameters. (.getCurve params)
      (.getG params)
      (.getN params)
      (.getH params))))

   :cljs
   (defonce
    ^{:doc "The secp256k1 curve object provided by SJCL that is used often"}
    curve ecc-curves/k256))
