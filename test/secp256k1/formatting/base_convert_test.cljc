(ns secp256k1.formatting.base-convert-test
  (:require [secp256k1.formatting.base-convert
             :refer [base-to-array
                     array-to-base]]
            #?(:clj  [clojure.test
                      :refer [is use-fixtures
                              testing are run-tests deftest]]
               :cljs [cljs.test
                      :refer-macros [is use-fixtures testing are]])
            #?(:cljs [devcards.core :refer-macros [deftest]])))

(deftest hex-test
  (is (= "05fb71a4f43ae66ac23544b87449b60bbb4874d18b3270eba29c5c057c7805a4"
         (-> "05fb71a4f43ae66ac23544b87449b60bbb4874d18b3270eba29c5c057c7805a4"
             (base-to-array :hex)
             (array-to-base :hex)))
      "`array-to-base` is the left inverse of `base-to-array`")
  (is (empty? (base-to-array "" :hex))
      "Empty string translates to empty array")
  (is (= "" (array-to-base [] :hex))
      "Empty array translates to empty string")
  (is (= "deadbeef" (array-to-base [0xDE 0xAD 0xBE 0xEF] :hex))
      "DEADBEEF array")
  (is (= "deadbeef" (-> []
                        (->> (cons 0xEF)
                             (cons 0xBE)
                             (cons 0xAD)
                             (cons 0xDE))
                        (array-to-base  :hex)))
      "DEADBEEF array (constructed)"))

(deftest base58-test
  (is (= "1111PmjXYHHyD76iU2VqVbM9rZDQqUspUt5TyXYC5fhF9"
         (-> "0000000071a4f43ae66ac23544b87449b60bbb4874d18b3270eba29c5c057c7805a4"
             (base-to-array :hex)
             (array-to-base :base58)))
      "`array-to-base` is the left inverse of `base-to-array`")
  (is (= "1111PmjXYHHyD76iU2VqVbM9rZDQqUspUt5TyXYC5fhF9"
         (-> "1111PmjXYHHyD76iU2VqVbM9rZDQqUspUt5TyXYC5fhF9"
             (base-to-array :base58)
             (array-to-base :base58)))
      "`array-to-base` is the left inverse of `base-to-array`"))

(comment (run-tests))
