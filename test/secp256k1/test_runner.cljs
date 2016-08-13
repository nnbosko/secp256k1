(ns secp256k1.test-runner
  (:require [secp256k1.core-test]
            [secp256k1.math-test]
            [secp256k1.formatting.der-encoding-test]
            [secp256k1.formatting.base-convert-test]
            [doo.runner :refer-macros [doo-tests]]))

(doo-tests 'secp256k1.core-test
           'secp256k1.math-test
           'secp256k1.formatting.der-encoding-test
           #_'secp256k1.formatting.base-convert-test
           )
