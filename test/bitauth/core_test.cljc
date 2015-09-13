(ns bitauth.core-test
  #?(:clj (:require [bitauth.core :as bitauth]
                    [clojure.test :refer :all]
                    [schema.test]))
  #?(:cljs (:require
            [bitauth.core :as bitauth]
            [schema.test]
            [cemerick.cljs.test
             :refer-macros [is deftest use-fixtures testing are]])))

(use-fixtures :once schema.test/validate-schemas)

(deftest get-public-key-from-private-key-with-leading-zero
  (is (= \0
         (-> "c6b7f6bfe5bb19b1e390e55ed4ba5df8af6068d0eb89379a33f9c19aacf6c08c"
             bitauth/get-public-key-from-private-key
             first))
      "Public key should start with a leading zero"))

(deftest known-results-tests
  (testing "A number of known priv-key, pub-key and SINs as reference"
    (let [priv-key "97811b691dd7ebaeb67977d158e1da2c4d3eaa4ee4e2555150628acade6b344c",
          pub-key "02326209e52f6f17e987ec27c56a1321acf3d68088b8fb634f232f12ccbc9a4575",
          sin "Tf3yr5tYvccKNVrE26BrPs6LWZRh8woHwjR"]
      (is (= pub-key (bitauth/get-public-key-from-private-key priv-key))
          "Public key k1 corresponds to private key")
      (is (= sin (bitauth/get-sin-from-public-key pub-key))))
    (let [priv-key "8295702b2273896ae085c3caebb02985cab02038251e10b6f67a14340edb51b0",
          pub-key "0333952d51e42f7db05a6c9dd347c4a7b4d4167ba29191ce1b86a0c0dd39bffb58",
          sin "TfJq16yg72aV9PqsZkhmiojuBRghdGWYcmj"]
      (is (= pub-key (bitauth/get-public-key-from-private-key priv-key))
          "Public key k1 corresponds to private key")
      (is (= sin (bitauth/get-sin-from-public-key pub-key))))
    (let [priv-key "e9d5516cb0ae45952fa11473a469587d6c0e8aeef3d6b0cca6f4497c725f314c",
          pub-key "033142109aba8e415c73defc83339dcec52f40ce762421c622347a7840294b3423",
          sin "Tewyxwicyc7dyteKAW1i47oFMc72HTtBckc"]
      (is (= pub-key (bitauth/get-public-key-from-private-key priv-key))
          "Public key k1 corresponds to private key")
      (is (= sin (bitauth/get-sin-from-public-key pub-key))))
    (let [priv-key "9e15c053f17c0991163073a73bc7e4b234c6c55c5f85bb397ed39f14c46a64bd",
          pub-key "02256b4b6062521370d21447914fae65deacd6a5d86347e6e69e66daab8616fae1",
          sin "TfJXKWBfHBSKf4ciN5LFPQTH5FxvsffvqNW"]
      (is (= pub-key (bitauth/get-public-key-from-private-key priv-key))
          "Public key k1 corresponds to private key")
      (is (= sin (bitauth/get-sin-from-public-key pub-key))))))

#?(:clj
   (deftest array-to-hex-conversion-and-back
     (testing "Can convert an array of bytes to hex"
       (is (= "ffffff" (#'bitauth/array-to-hex [0xFF 0xFF 0xFF])))
       (is (= "aaaaaa" (#'bitauth/array-to-hex [0xAA 0xAA 0xAA]))))
     (testing "Can convert an array of bytes to hex back and forth"
       (is (= "00ffffff" (-> [0x00 0xFF 0xFF 0xFF] ;; 32 bits
                             (#'bitauth/array-to-hex)
                             (#'bitauth/hex-to-array)
                             (#'bitauth/array-to-hex))))
       (is (= "00aaaaaa" (-> [0x00 0xAA 0xAA 0xAA]
                             (#'bitauth/array-to-hex)
                             (#'bitauth/hex-to-array)
                             (#'bitauth/array-to-hex)))))))

#?(:clj
   (deftest x962-point-encode-decode
     (testing "x962-point-encode is the left inverse of x962-point-decode"
       (letfn [(encode-decode [x]
                              (#'bitauth/x962-point-encode
                               (#'bitauth/x962-point-decode x)))]
         (are [y] (= y (encode-decode y))
           "02256b4b6062521370d21447914fae65deacd6a5d86347e6e69e66daab8616fae1"
           "0333952d51e42f7db05a6c9dd347c4a7b4d4167ba29191ce1b86a0c0dd39bffb58"
           "03816a53aded6d63ae34c2e87addba7532c096c4e2bcfc95f1ecfc7d78e0bad846"
           "0233bdfb75729492c8203320ef900c6f38f98e3c92cc93ac13c5fdf268828b8cd1"
           "02e64efe4258a418e33087f818ea5f8ac9ce7b00b4ba1ce469423dd0abbc7d478e"
           "03fe4e1d6fd5e3098e8fa9e2bedb3340aac95d14549231d0a8c7c72853db5d574c"
           "033502a164ed317f5d2278e79a75db9b3ef98616efec53925b22c75999fdcb8ab9"
           "0387efe8c69a2cfbba735afd486b07bd85b7749dd19c5772da30564652ec7e84c5")))))

(deftest sign-tests
  (testing "Signed messages can be checked with a proper pub key"
    (let [priv-key "97811b691dd7ebaeb67977d158e1da2c4d3eaa4ee4e2555150628acade6b344c",
          pub-key (bitauth/get-public-key-from-private-key priv-key)]
      (are [x] (bitauth/verify-signature x pub-key (bitauth/sign x priv-key))
        "foo"
        "bar"
        "yabba dabba dooo"
        "I wanna hold 'em like they do in Texas, please
            Fold 'em, let 'em, hit me, raise it, baby, stay with me (I love it)
            Love game intuition play the cards with Spades to start
            And after he's been hooked I'll play the one that's on his heart")))
  (testing "Reference signatures"
    (let [priv-key "8295702b2273896ae085c3caebb02985cab02038251e10b6f67a14340edb51b0"
          pub-key (bitauth/get-public-key-from-private-key priv-key)]
      (is (bitauth/verify-signature
           "foo" pub-key
           "3046022100927247ae8b1d692d99096ea0a352ca99a4af84377af8152ccca671f24bc6169702210093c2d746fda29e73df9ed3b0221980f98fefce88a6842e75f746b3f601a10860"))
      (is (bitauth/verify-signature
           "baz" pub-key
           "304502207112050031f6c7d8bb9b7b25dee49c7efcf11517c6c62f5003549d4c0458fe56022100ca39bd15863e0aee5872730c36fd73da2e303df261d548b25a374cf80ee71516"))
      (is (bitauth/verify-signature
           "What a piece of work is a man! how noble in reason! how infinite in faculty! in form and moving how express and admirable! in action how like an angel! in apprehension how like a god!" pub-key
           "3045022100f05b856e296db0cf17b31a1c5919801cdb3607a528bcfeb506b530e3509820aa02201ad38516d2801d01a609d45a233d69f52a465851d3b1da983c3437b762262eb9")))))

(deftest sin-tests
  (testing "Reference sins are valid"
    (are [x] (bitauth/validate-sin x)
      "TfKAQBFY3FPixJGVp81TWbjMdv2ftnZ8CRL"
      "TfGVzWqwft6fFdLzy8vR7qFTT77N7aTqa4n"
      "Tf4Lo9zAU73ezP7LKc3njaK5pez7oVhzH2H"
      "Tf7EsXB155iZ1aMkxh5ZyUJ7rTAyaZ6CFeT"
      "TexcsXqvbqeVrfpHQur5HvBqqQqBWB9XEsD"
      "TfBZ3DacgxVbemggEXZtHxoNXgD5FWi2cLD"
      "TfFc5Rh5NFFY6EsGcY6xe6vSct2hCWzk25X")))

(deftest full-test
  (testing "Can generate a private key, public key, and SIN"
    (let [{:keys [:priv :pub :sin]} (bitauth/generate-sin)]
      (is (= pub (bitauth/get-public-key-from-private-key priv)))
      (is (= sin (-> priv
                     bitauth/get-public-key-from-private-key
                     bitauth/get-sin-from-public-key)))
      (is (bitauth/validate-sin sin))
      (are [x] (bitauth/verify-signature x pub (bitauth/sign x priv))
        "trololololol"
        "TfKAQBFY3FPixJGVp81TWbjMdv2ftnZ8CRL"
        "TfGVzWqwft6fFdLzy8vR7qFTT77N7aTqa4n"
        "Tf4Lo9zAU73ezP7LKc3njaK5pez7oVhzH2H"
        "Tf7EsXB155iZ1aMkxh5ZyUJ7rTAyaZ6CFeT"
        "TexcsXqvbqeVrfpHQur5HvBqqQqBWB9XEsD"
        "TfBZ3DacgxVbemggEXZtHxoNXgD5FWi2cLD"
        "TfFc5Rh5NFFY6EsGcY6xe6vSct2hCWzk25X"))))

(comment (run-tests))
