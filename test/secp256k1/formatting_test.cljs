(ns secp256k1.formatting-test
  (:require [cljs.test :refer-macros [is use-fixtures testing are]]
            [devcards.core :refer-macros [deftest]]
            [secp256k1.formatting :as formatting]
            [schema.test]))

(deftest integer-encoding-tests
  (testing "Can encode some known integers"
    (is (= "0220657912a72d3ac8169fe8eaecd5ab401c94fc9981717e3e6dd4971889f785790c"
           (formatting/encode-asn1-unsigned-integer
            "657912a72d3ac8169fe8eaecd5ab401c94fc9981717e3e6dd4971889f785790c")))
    (is (= "022100ed3bf3456eb76677fd899c8ccd1cc6d1ebc631b94c42f7c4578f28590d651c6e"
           (formatting/encode-asn1-unsigned-integer
            "00ed3bf3456eb76677fd899c8ccd1cc6d1ebc631b94c42f7c4578f28590d651c6e")))
    (is (= "0241049b5506df53ff5eff7dc553131043bb993f55d2b0fddd866984f593777023c8226920ff05747ccb963f0fe459cb217d502e57dcf8afec786c3dcee4d1558f85fa"
           (formatting/encode-asn1-unsigned-integer
            "049b5506df53ff5eff7dc553131043bb993f55d2b0fddd866984f593777023c8226920ff05747ccb963f0fe459cb217d502e57dcf8afec786c3dcee4d1558f85fa"))))

  (testing "Can decode integers"
    (is (= {:integer "049b5506df53ff5eff7dc553131043bb993f55d2b0fddd866984f593777023c8226920ff05747ccb963f0fe459cb217d502e57dcf8afec786c3dcee4d1558f85fa"
            :remaining ""}
           (formatting/decode-asn1-integer
            "0241049b5506df53ff5eff7dc553131043bb993f55d2b0fddd866984f593777023c8226920ff05747ccb963f0fe459cb217d502e57dcf8afec786c3dcee4d1558f85fa"))))

  (testing "Can encode and decode integers"
    (are [x] (= x (-> x
                      formatting/encode-asn1-unsigned-integer
                      formatting/decode-asn1-integer
                      :integer))
      "00ed3bf3456eb76677fd899c8ccd1cc6d1ebc631b94c42f7c4578f28590d651c6e"
      "049b5506df53ff5eff7dc553131043bb993f55d2b0fddd866984f593777023c8226920ff05747ccb963f0fe459cb217d502e57dcf8afec786c3dcee4d1558f85fa")))

(deftest DER-tests
  (testing "Can encode a pair of known integers"
    (is (= "30450220657912a72d3ac8169fe8eaecd5ab401c94fc9981717e3e6dd4971889f785790c022100ed3bf3456eb76677fd899c8ccd1cc6d1ebc631b94c42f7c4578f28590d651c6e"
           (formatting/DER-encode
            ["657912a72d3ac8169fe8eaecd5ab401c94fc9981717e3e6dd4971889f785790c"
             "00ed3bf3456eb76677fd899c8ccd1cc6d1ebc631b94c42f7c4578f28590d651c6e"])))
    (is (= "3044022045bc5aba353f97316b92996c01eba6e0b0cb63a763d26898a561c748a9545c7502204dc0374c8d4ca489c161b21ff5e25714f1046d759ec9adf9440233069d584567"
           (formatting/DER-encode
            ["45bc5aba353f97316b92996c01eba6e0b0cb63a763d26898a561c748a9545c75"
             "4dc0374c8d4ca489c161b21ff5e25714f1046d759ec9adf9440233069d584567"]))))
  (testing "Can encode and decode integers"
    (are [x] (= x (-> x formatting/DER-encode formatting/DER-decode))
      ["45bc5aba353f97316b92996c01eba6e0b0cb63a763d26898a561c748a9545c75"
       "4dc0374c8d4ca489c161b21ff5e25714f1046d759ec9adf9440233069d584567"]
      ["657912a72d3ac8169fe8eaecd5ab401c94fc9981717e3e6dd4971889f785790c"
       "00ed3bf3456eb76677fd899c8ccd1cc6d1ebc631b94c42f7c4578f28590d651c6e"]))
  (testing "Can encode a signature"
    (is (= "3044022045bc5aba353f97316b92996c01eba6e0b0cb63a763d26898a561c748a9545c7502204dc0374c8d4ca489c161b21ff5e25714f1046d759ec9adf9440233069d584567"
           (formatting/DER-encode-ECDSA-signature
            :R "45bc5aba353f97316b92996c01eba6e0b0cb63a763d26898a561c748a9545c75"
            :S "4dc0374c8d4ca489c161b21ff5e25714f1046d759ec9adf9440233069d584567"))))
  (testing "Can decode a signature"
    (is (= {:R "45bc5aba353f97316b92996c01eba6e0b0cb63a763d26898a561c748a9545c75"
            :S "4dc0374c8d4ca489c161b21ff5e25714f1046d759ec9adf9440233069d584567"
            :recover nil}
           (formatting/DER-decode-ECDSA-signature
            (formatting/DER-encode-ECDSA-signature
             :R "45bc5aba353f97316b92996c01eba6e0b0cb63a763d26898a561c748a9545c75"
             :S "4dc0374c8d4ca489c161b21ff5e25714f1046d759ec9adf9440233069d584567"))))))
