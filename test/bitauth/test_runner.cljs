(ns bitauth.test-runner
  (:require [bitauth.core-test]
            [bitauth.math-test]
            [bitauth.formatting-test]
            [doo.runner :refer-macros [doo-tests]]))

(doo-tests 'bitauth.core-test 'bitauth.math-test 'bitauth.formatting-test)
