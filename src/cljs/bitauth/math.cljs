(ns bitauth.math
  (:refer-clojure :exclude [even?])
  (:require [sjcl]))

(defn even?
  "Patch the usual cljs.core/even? to work for sjcl.bn instances"
  [n]
  (if (instance? js/sjcl.bn n)
    (.equals (.mod n 2) 0)
    (cljs.core/even? n)))

(defn modular-square-root
  "Compute the square root of a number modulo a prime"
  [n modulus]
  (let [modulus (new js/sjcl.bn modulus)
        n       (.mod (new js/sjcl.bn n) modulus)
        mod8    (-> modulus (.mod 8) .toString js/parseInt)]
    (assert (.greaterEquals n 2),
            "Argument must be greater than or equal to 2")
    (assert (.greaterEquals modulus 0),
            "Modulus must be non-negative")
    (cond
      ;; http://www.mersennewiki.org/index.php/Modular_Square_Root#Modulus_equal_to_2
      (.equals modulus 2)
      (.mod n modulus)

      ;; http://www.mersennewiki.org/index.php/Modular_Square_Root#Modulus_congruent_to_3_modulo_4
      (or (= mod8 3) (= mod8 7))
      (let [m (-> modulus (.add 1) .normalize .halveM .halveM)]
        (.powermod n m modulus))

      ;; http://www.mersennewiki.org/index.php/Modular_Square_Root#Modulus_congruent_to_5_modulo_8
      (= mod8 5)
      (let [m (-> modulus (.sub 5) .normalize .halveM .halveM .halveM)
            v (.powermod (.add n n) m modulus)
            i (-> (.mul v v) (.mul n) (.mul 2) (.sub 1) (.mod modulus))]
        (-> n (.mul v) (.mul i) (.mod modulus)))

      ;; http://www.mersennewiki.org/index.php/Modular_Square_Root#Modulus_congruent_to_1_modulo_8
      (= mod8 1)
      (let [q   (-> modulus (.sub 1) .normalize)
            e   (->> q
                     (iterate #(.halveM %))
                     (take-while even?)
                     count)
            two (new js/sjcl.bn 2)
            z   (->> (range) rest rest
                     (map #(new js/sjcl.bn %))
                     (map #(.powermod % q modulus))
                     (filter
                      #(not
                        (.equals
                         (.powermod % (.power two (- e 1)) modulus)
                         1)))
                     first)
            x   (.powermod n (-> q (.sub 1) .normalize .halveM) modulus)]
        (loop [y z,
               r e,
               v (-> n (.mul x) (.mod modulus)),
               w (-> n (.mul x) (.mul x) (.mod modulus))]
          (if (.equals w 1)
            v
            (let [k (->> (range)
                         (map #(vector
                                %
                                (.powermod w (.power two %) modulus)))
                         (filter #(.equals (second %) 1))
                         first first)
                  d (.powermod y (.power two (- r k 1)) modulus)
                  y (.mod (.mul d d) modulus)
                  v (.mod (.mul d v) modulus)
                  w (.mod (.mul w y) modulus)]
              (recur y k v w)))))

      :else
      (throw (ex-info "Cannot compute a square root for a non-prime modulus"
                      {:argument n,
                       :modulus modulus})))))
