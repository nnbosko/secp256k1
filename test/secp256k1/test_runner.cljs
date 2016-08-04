(ns secp256k1.test-runner
  (:require [secp256k1.core-test]
            [secp256k1.math-test]
            [secp256k1.formatting-test]
            [doo.runner :refer-macros [doo-tests]]))

(doo-tests 'secp256k1.core-test 'secp256k1.math-test 'secp256k1.formatting-test)
