(ns secp256k1.math-test
  (:require [cljs.test :refer-macros [is use-fixtures testing are]]
            [devcards.core :refer-macros [deftest]]
            [secp256k1.math :refer [modular-square-root]])
  (:import [secp256k1.math.random Isaac]))

(deftest modular-square-root-607
  (testing "Can compute square roots modulo 607 (= 3 mod 8)"
    (let [prime 607
          n (-> (js/Math.random) (* 1000) js/Math.floor (js/Math.pow 2))
          root (modular-square-root n prime)]
      (is
       (= (mod n prime)
          (-> root
              .square
              (.mod prime)
              .toString
              js/parseInt))))))

(deftest modular-square-root-7933
  (testing "Can compute square roots modulo 7933 (= 5 mod 8)"
    (let [prime 7933
          n (-> (js/Math.random) (* 1000) js/Math.floor (js/Math.pow 2))
          root (modular-square-root n prime)]
      (is
       (= (mod n prime)
          (-> root
              .square
              (.mod prime)
              .toString
              js/parseInt))))))


(deftest modular-square-root-7937
  (testing "Can compute square roots modulo 7937 (= 1 mod 8)"
    (let [prime 7937
          n (-> (js/Math.random) (* 1000) js/Math.floor (js/Math.pow 2))
          root (modular-square-root n prime)]
      (is
       (= (mod n prime)
          (-> root
              .square
              (.mod prime)
              .toString
              js/parseInt))))))

(deftest isaac-js
  (testing "Isaac.js has basic functionality"
    (is (integer? (-> (new Isaac) .rand)))
    (is (pos? (-> (new Isaac) .rand)))
    (is (= 3967595742 (-> (new Isaac) (.seed 5) .rand)))))
