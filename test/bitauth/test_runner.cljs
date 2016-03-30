(ns bitauth.test-runner
  (:require [bitauth.core-test]
            [doo.runner :refer-macros [doo-tests]]))

(doo-tests 'bitauth.core-test)
