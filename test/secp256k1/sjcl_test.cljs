(ns secp256k1.sjcl-test
  (:require
    [clojure.test :refer [is use-fixtures testing are]]
    [devcards.core :refer [deftest defcard]]
    [secp256k1.math :refer [modular-square-root]]
    [secp256k1.sjcl.bn]
    [secp256k1.core]
    [secp256k1.sjcl.ecc.curves :as ecc-curves]
    [secp256k1.sjcl.ecc.ECPoint :as ecc-ecpoint]
    [secp256k1.sjcl.bn.prime :as prime]
    [goog.array :as array])
  (:import [secp256k1.sjcl bn]
           [secp256k1.sjcl.ecc ECPoint]))


(deftest bn-hello-world
  (testing "Can make a `secp256k1.sjcl.bn`"
    (is (.equals (bn. 1) (new bn "1"))))
  (testing "Can square an `secp256k1.sjcl.bn`"
    (is (.equals (.square (bn. 2)) (new bn "4"))))
  (testing "Multiplication works"
    (is (= (bn. 4)
          (-> (new bn 2) (.mul 2)))))
  (testing "Modular Multiplication works"
    (is (= (bn. 1)
          (-> (new bn 2) (.mulmod 2 3)))))
  (testing "Can copy"
    (is (= (bn. 2)
          (-> (new bn 2) .copy)))))


(deftest bn-equality-testing
  (testing "Equality works for `secp256k1.sjcl.bn`"
    (is (array/equals
          (-> 1 bn. .-limbs)
          (-> (new bn "1") .-limbs)))
    (is (= (bn. 1) (new bn "1")))
    (is (= (bn. "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f")
          (new bn "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f")))
    (is (= (-> "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"
             bn.
             .toBits
             secp256k1.sjcl.bn/fromBits)
          (new bn "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f")))))

(deftest prime-field-test
  (testing "Prime fields let you construct points that inherit from bn"
    (is (instance? bn (bn. 2))))
  (testing "Field points can be normalized"
    (is (= (bn. 2)
          (-> (bn. 2) .normalize))))
  (testing "Field points can be converted to bits and back"
    (is (= (bn. 2)
          (-> (bn. 2) .toBits secp256k1.sjcl.bn/fromBits))))
  (testing "Multiplication works for Field points"
    (is (= (bn. 4)
          (-> (bn. 2) (.mul 2)))))
  (testing "Power works for Field points"
    (is (= "0x100000"
          (-> (bn. 2) (.power 20) .toString)))
    (is (= "0x10000000000"
          (-> (bn. 2) (.power 40) .toString)))
    (is (= "0x10000000000000000000000000"
          (-> (bn. 2) (.power 100) .toString)))
    (is (= "0x100000000000000000000000000000000000000000000000000"
          (-> (bn. 2) (.power 200) .toString)))
    (is (= "0x100000000000000000000000000000000000000000000000000"
          (-> (bn. 2) (.power 200) .normalize .toString)))
    (is (= "0x100000000000000000000000000000000000000000000000000"
          (-> (bn. 2) (.power 200) (prime/reduce prime/p256k) .toString)))
    (is (= "0x100000000000000000000000000000000000000000000000000"
          (-> (bn. 2) (.power 200) (prime/fullReduce prime/p256k)  .toString)))
    (is (= "0x1000000000000000000000000000000000000000000000000000000000000000000000000000"
          (-> (bn. 2) (.power 300) .toString)))
    (is (= "0x1000000000000000000000000000000000000000000000000000000000000000000000000000"
          (-> (bn. 2) (.power 300) .normalize .toString)))
    (is (= "0x1000003d100000000000"
          (-> (bn. 2) (.powermod 300 prime/p256k.modulus) .toString))))
  (testing "Fermat's little theorem holds"
    (is (instance? bn prime/p256k.modulus)
      "Modulus is a BigNum")
    (is (= prime/p256k.modulus (.copy prime/p256k.modulus))
      "Modulus is a BigNum")
    (is (= secp256k1.sjcl.bn.ONE
          (->
            (bn. 2)
            (.powermod (.sub prime/p256k.modulus 1) prime/p256k.modulus))))
    (is (= secp256k1.sjcl.bn.ONE
          (->
            (bn. 123123)
            (.powermod (.sub prime/p256k.modulus 1) prime/p256k.modulus))))
    )
  (testing "Modular inverse works"
    (is (= secp256k1.sjcl.bn.ONE
          (->
            (bn. 2)
            (.powermod (.sub prime/p256k.modulus 2) prime/p256k.modulus)
            (.mul 2)
            (.mod prime/p256k.modulus))))
    (is (= secp256k1.sjcl.bn.ONE
          (->
            (bn. 2)
            (.inverseMod prime/p256k.modulus)
            (.mul 2)
            (.mod prime/p256k.modulus))))
    (is (= secp256k1.sjcl.bn.ONE
          (->
            (bn. 123123213)
            (.inverseMod prime/p256k.modulus)
            (.mul 123123213)
            (.mod prime/p256k.modulus))))))

(deftest ECC-tests
  (testing "SECP256k1 exists"
    (is (exists? ecc-curves/k256)))
  (testing "Can get generator"
    (is (exists? ecc-curves/k256.G))
    (is (instance? ECPoint ecc-curves/k256.G)))
  (testing "Equality works for generator points"
    (is (= ecc-curves/k256.G ecc-curves/k256.G))
    (is (= ecc-curves/k256.G (-> ecc-curves/k256.G .toJac .toAffine))
      "Can convert to Jacobian Point and Back")
    (is (= "0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
          (-> ecc-curves/k256.G .-x .toString))))
  (testing "Can Double Jacobian point"
    (is (= "0xc6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
          (-> ecc-curves/k256.G .toJac .doubl .toAffine .-x .toString))
      "Can convert to Jacobian Point, Double and Convert and Back and take x coordinate")
    (is (= "0x1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a"
          (-> ecc-curves/k256.G .toJac .doubl .toAffine .-y .toString))
      "Can convert to Jacobian Point, Double and Convert and Back and take y coordinate")
    (is (not=
          ecc-curves/k256.G
          (-> ecc-curves/k256.G .toJac .doubl .toAffine))
      "A sad path for equality: the generator point isn't equal to its doubling"))
  (testing "Adding a point to itself is the same as doubling"
    (is (= (let [G-Jac (.toJac ecc-curves/k256.G)]
            (-> G-Jac (.add ecc-curves/k256.G) .toAffine .-x .toString))
          (let [G-Jac (.toJac ecc-curves/k256.G)]
            (-> G-Jac .doubl .toAffine .-x .toString))
          "0xc6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")))
  (testing "Can add a point to its double"
    (is (= (let [G-Jac (.toJac ecc-curves/k256.G)]
            (-> G-Jac .doubl (.add ecc-curves/k256.G) .toAffine .-x .toString))
          "0xf9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"))
    (is (= (let [G-Jac (.toJac ecc-curves/k256.G)]
            (-> G-Jac .doubl (.add ecc-curves/k256.G) .toAffine .-y .toString))
          "0x388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672")))
  (testing "Can get multiples of a point"
    (is (= true
          (-> ecc-curves/k256.G .multiples first .-isIdentity)))
    (is (= false
          (-> ecc-curves/k256.G .multiples second .-isIdentity)))
    (is (= "0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
          (-> ecc-curves/k256.G .multiples second .-x .toString)))
    (is (= "0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
          (-> ecc-curves/k256.G .multiples second .-y .toString)))
    (is (= ecc-curves/k256.G
          (-> ecc-curves/k256.G .multiples second)))
    (is (= 16
          (count (.multiples ecc-curves/k256.G))))
    (is (every? #(instance? ECPoint %) (.multiples ecc-curves/k256.G))))
  (testing "Can negate a point"
    (is (= "0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
          (-> ecc-curves/k256.G .negate .-x .toString)))
    (is (= "0xb7c52588d95c3b9aa25b0403f1eef75702e84bb7597aabe663b82f6f04ef2777"
          (-> ecc-curves/k256.G .negate .-y .toString)))
    (is (not= ecc-curves/k256.G
          (.negate ecc-curves/k256.G)))
    (is (= true (let [G-Jac (.toJac ecc-curves/k256.G)]
                  (-> G-Jac
                    (.add (.negate ecc-curves/k256.G))
                    .toAffine
                    .-isIdentity)))
      "Adding a point to its inverse yields the identity")
    (is (= (ecc-ecpoint/identity ecc-curves/k256)
          (let [G-Jac (.toJac ecc-curves/k256.G)]
                  (-> G-Jac
                    (.add (.negate ecc-curves/k256.G))
                    .toAffine)))
      "Adding a point to its inverse yields the identity (comparing directly)")
    (is (= (ecc-ecpoint/identity ecc-curves/k256)
          (let [G-Jac (.toJac ecc-curves/k256.G)]
            (-> G-Jac
              (.add (-> G-Jac .negate .toAffine))
              .toAffine)))
      "Adding a point to its inverse (calculated using Jacobian coordinates) yields the identity"))
  (testing "Can multiply a point"
    (is (= "0x4a5169f673aa632f538aaa128b6348536db2b637fd89073d49b6a23879cdb3ad"
          (-> ecc-curves/k256.G (.mult 1000) .-x .toString))))
  (testing "Can check if a point is valid or not"
    (is (.isValid ecc-curves/k256.G)
      "Generator point is valid")
    (is (.isValid (.mult ecc-curves/k256.G "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"))
      "Generator • 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF is valid")
    (is (not (.isValid (ECPoint. ecc-curves/k256 123 123)))
      "Sad Path: Silly point is not valid")
    (is (-> ecc-curves/k256.G .toJac .isValid)
      "Generator point is valid (using Jacobian coordinates)")))