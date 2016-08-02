(ns bitauth.core-test
  (:require [bitauth.core :as bitauth]
            #?(:clj [bitauth.hashes :as hashes])
            #?(:clj  [clojure.test :refer [is use-fixtures testing are run-tests deftest]]
               :cljs [cljs.test :refer-macros [is use-fixtures testing are]])
            #?(:cljs [devcards.core :refer-macros [deftest]])
            [schema.test])
  #?(:clj (:import javax.xml.bind.DatatypeConverter)))

(use-fixtures :once schema.test/validate-schemas)

(deftest get-public-key-from-private-key-with-leading-zero
  (is (= "0200bf0e38b86329f84ea90972e0f901d5ea0145f1ebac8c50fded77796d7a70e1"
         (bitauth/get-public-key-from-private-key
          "c6b7f6bfe5bb19b1e390e55ed4ba5df8af6068d0eb89379a33f9c19aacf6c08c"))
      "Public key should start with a leading zero")
  (is (= "0400bf0e38b86329f84ea90972e0f901d5ea0145f1ebac8c50fded77796d7a70e1be9e001b7ece071fb3986b5e96699fe28dbdeec8956682da78a5f6a115b9f14c"
         (bitauth/get-public-key-from-private-key
          "c6b7f6bfe5bb19b1e390e55ed4ba5df8af6068d0eb89379a33f9c19aacf6c08c" :compressed false))
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
   (deftest hmac-SHA256
     (testing "Returns the right result for reference HMAC-SHA256 values from wikipedia: https://en.wikipedia.org/wiki/Hash-based_message_authentication_code#Examples"
       (is (= "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad"
              (-> (hashes/hmac-sha256 "" "")
                  DatatypeConverter/printHexBinary .toLowerCase)))
       (is (= "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
              (-> (hashes/hmac-sha256
                   "key"
                   "The quick brown fox jumps over the lazy dog")
                  DatatypeConverter/printHexBinary .toLowerCase))))))

(deftest x962-point-encode-decode
  (testing "x962-point-encode is the left inverse of x962-point-decode"
    (letfn [(encode-decode [x]
              (bitauth/x962-point-encode
               (bitauth/x962-point-decode x)))]
      (are [y] (= y (encode-decode y))
        "02256b4b6062521370d21447914fae65deacd6a5d86347e6e69e66daab8616fae1"
        "0333952d51e42f7db05a6c9dd347c4a7b4d4167ba29191ce1b86a0c0dd39bffb58"
        "03816a53aded6d63ae34c2e87addba7532c096c4e2bcfc95f1ecfc7d78e0bad846"
        "0233bdfb75729492c8203320ef900c6f38f98e3c92cc93ac13c5fdf268828b8cd1"
        "02e64efe4258a418e33087f818ea5f8ac9ce7b00b4ba1ce469423dd0abbc7d478e"
        "03fe4e1d6fd5e3098e8fa9e2bedb3340aac95d14549231d0a8c7c72853db5d574c"
        "033502a164ed317f5d2278e79a75db9b3ef98616efec53925b22c75999fdcb8ab9"
        "0387efe8c69a2cfbba735afd486b07bd85b7749dd19c5772da30564652ec7e84c5")))

  (testing "x962-point-encode is the left inverse of x962-point-decode (uncompressed)"
    (letfn [(encode-decode [x]
              (-> x
                  bitauth/x962-point-decode
                  (bitauth/x962-point-encode :compressed false)
                  (bitauth/x962-point-encode :compressed false)
                  bitauth/x962-point-decode
                  bitauth/x962-point-decode
                  bitauth/x962-point-encode
                  (bitauth/x962-point-encode :compressed false)
                  bitauth/x962-point-encode
                  (bitauth/x962-point-encode :compressed false)))]
      (are [y] (= y (encode-decode y))
        "04256b4b6062521370d21447914fae65deacd6a5d86347e6e69e66daab8616fae1ca81c29a7307b6c77182b77ce9699b6b2940610b2306825fd38a475dd3c804c4"
        "0433952d51e42f7db05a6c9dd347c4a7b4d4167ba29191ce1b86a0c0dd39bffb58a002d2f3b46b55c54d1780c176119497cb81b0ace382227f2a6b8b3ba1eccd83"
        "04816a53aded6d63ae34c2e87addba7532c096c4e2bcfc95f1ecfc7d78e0bad846eea75ae3bd6a053582d362a054129567ff2e0c4877e7b2a4d958913121b099f7"
        "0433bdfb75729492c8203320ef900c6f38f98e3c92cc93ac13c5fdf268828b8cd11880422a1640df75f9601927e09b6c053e0aef740f52fc4b341e750891294210"
        "04e64efe4258a418e33087f818ea5f8ac9ce7b00b4ba1ce469423dd0abbc7d478e02cd25f31fd29119c7259840b97855156f3a9ac52f7ae0cb69c22695e649d2fc"
        "04fe4e1d6fd5e3098e8fa9e2bedb3340aac95d14549231d0a8c7c72853db5d574c07532c7c1481771989377bb0a7820c554c272fd77cdf2dac55f3aa1eca82eaf5"
        "043502a164ed317f5d2278e79a75db9b3ef98616efec53925b22c75999fdcb8ab9dd3c65e83963adac704e5782b5f886280a8c4960f1e49152b139bfd05862c7af"
        "0487efe8c69a2cfbba735afd486b07bd85b7749dd19c5772da30564652ec7e84c5aa43aaed73348f97b306145ce0544078210f7e587c675805ccc0933d6673c979")))

  (testing "x962-point-encoding twice is idempotent"
    (letfn [(encode-decode [x]
              (bitauth/x962-point-encode
               (bitauth/x962-point-encode
                (bitauth/x962-point-decode x))))]
      (are [y] (= y (encode-decode y))
        "02256b4b6062521370d21447914fae65deacd6a5d86347e6e69e66daab8616fae1"
        "0333952d51e42f7db05a6c9dd347c4a7b4d4167ba29191ce1b86a0c0dd39bffb58"
        "03816a53aded6d63ae34c2e87addba7532c096c4e2bcfc95f1ecfc7d78e0bad846"
        "0233bdfb75729492c8203320ef900c6f38f98e3c92cc93ac13c5fdf268828b8cd1"
        "02e64efe4258a418e33087f818ea5f8ac9ce7b00b4ba1ce469423dd0abbc7d478e"
        "03fe4e1d6fd5e3098e8fa9e2bedb3340aac95d14549231d0a8c7c72853db5d574c"
        "033502a164ed317f5d2278e79a75db9b3ef98616efec53925b22c75999fdcb8ab9"
        "0387efe8c69a2cfbba735afd486b07bd85b7749dd19c5772da30564652ec7e84c5"))))

(deftest sign-tests
  (testing "Signed messages can be checked with a proper pub key"
    (let [priv-key "97811b691dd7ebaeb67977d158e1da2c4d3eaa4ee4e2555150628acade6b344c",
          pub-key (bitauth/get-public-key-from-private-key priv-key)]
      (are [x] (bitauth/verify-signature pub-key x (bitauth/sign priv-key x))
        "foo"

        "bar"

        "yabba dabba dooo"

        "I wanna hold 'em like they do in Texas, please
         Fold 'em, let 'em, hit me, raise it, baby, stay with me (I love it)
         Love game intuition play the cards with Spades to start
         And after he's been hooked I'll play the one that's on his heart"

        "☕️   ⓝ  🀤  ⎈  ∲"

        "इसकी दो प्रजातियाँ हैं सुपर्ब लायर बर्ड तथा अलबर्ट्स लायर बर्ड"

        "금조류(琴鳥類, lyrebird)는 오스트레일리아 남부에 사는 참새목의 한 부류로, 주변의 소리를 잘 따라한다. 거문고새라고도 한다."

        "コトドリ属（コトドリぞく、学名 Menura）はコトドリ上科コトドリ科 Menuridae に属する鳥の属の一つ。コトドリ科は単型である。")))

  (testing "Reference signatures"
    (let [priv-key "8295702b2273896ae085c3caebb02985cab02038251e10b6f67a14340edb51b0"
          pub-key (bitauth/get-public-key-from-private-key priv-key)]
      (are [x y] (bitauth/verify-signature pub-key x y)
        "foo"
        "3044022045bc5aba353f97316b92996c01eba6e0b0cb63a763d26898a561c748a9545c7502204dc0374c8d4ca489c161b21ff5e25714f1046d759ec9adf9440233069d584567",

        "baz"
        "304502206ac2ffc240d23fd218a5aa9857065b8bb09ed6c154f1d7da2b56f993bd6e1e3e022100e8dba80dea09122ab87aae82f91e23876aa6628055e24afc895405482ac97aae",

        "What a piece of work is a man! how noble in reason! how infinite in faculty! in form and moving how express and admirable! in action how like an angel! in apprehension how like a god!",
        "304402204c818a10380ba42b3be0a293d47922469c4ae7ad6277e0e62bf32700c79c32210220102b673477ee13877b4b7f8f9a2e4c2004553948fbe5e7fd95d7e23b4cd9f8e3",

        "☕️   ⓝ  🀤  ⎈  ∲"
        "304502204d78e57e9bce7fc6d3dd61bcd1baaceff2689f9a8efac5bbb8ce59a47f6652120221008bdce60d43916e35db9c8ee889ba2f85acd2a98fa0193cce0a7f9f9d9867aac1",

        "इसकी दो प्रजातियाँ हैं सुपर्ब लायर बर्ड तथा अलबर्ट्स लायर बर्ड"
        "304602210087d7aad4dc2789b8f58f97f541f95fc150ffc7fad8e09093932c023b13330e1a022100b434f9403048a983f8dfbd9b92ad8e2dac1ec4b1934dec8c94f4165bf981e01c",

        "금조류(琴鳥類, lyrebird)는 오스트레일리아 남부에 사는 참새목의 한 부류로, 주변의 소리를 잘 따라한다. 거문고새라고도 한다."
        "3044022030e9acbd8f0f3328bd059296092824a38216a222d04ac7e1f3de89d4270f3e18022014386f61154177111fe1da0eee9874e612990d3ce663e6f2b4c44828b4c7072f",

        "コトドリ属（コトドリぞく、学名 Menura）はコトドリ上科コトドリ科 Menuridae に属する鳥の属の一つ。コトドリ科は単型である。",
        "3046022100b286833ddce1537e12f56ae63fbbd6db25ac0dfab659d342a323b764765b60c0022100d83878b0529bf2cab70e98929faf11d1836d8452ef978aad558e35cce4fb14c4",

        "ဂျူးလိယက်ဆီဇာ(ဘီစီ၁၀၀-၄၄)"
        "304402206ba84011c961db733e28f40f2496e8ff1ba60fcbf942b609fd1a9a6971f22e5b02202987d7d6ad5c330c7fdacefe3351554c00f42b82b7ad513104de8caebae40fc8",

        "རོ་མའི་རང་དབང་འབངས་མི་ཞིག་ལ་མིང་གསུམ་ཡོད་དེ།"
        "304402200e4b0560c42e4de19ddc2541f5531f7614628e9d01503d730ebe38c182baee8702206b80868e3d67fec2a9d5a594edd6b4f0266044965fe41e7cc3bff65feb922b7c")))

  (testing "Bad signatures"
    (let [priv-key "8295702b2273896ae085c3caebb02985cab02038251e10b6f67a14340edb51b0"
          pub-key (bitauth/get-public-key-from-private-key priv-key)]
      (are [x y] (not (bitauth/verify-signature pub-key x y))
        5
        "3044022045bc5aba353f97316b92996c01eba6e0b0cb63a763d26898a561c748a9545c7502204dc0374c8d4ca489c161b21ff5e25714f1046d759ec9adf9440233069d584567",

        "baz"
        "XXX304502206ac2ffc240d23fd218a5aa9857065b8bb09ed6c154f1d7da2b56f993bd6e1e3e022100e8dba80dea09122ab87aae82f91e23876aa6628055e24afc895405482ac97aae",

        "What a piece of work is a man! how noble in reason! how infinite in faculty! in form and moving how express and admirable! in action how like an angel! in apprehension how like a god!",
        :foo,

        nil
        "304502204d78e57f2689f9a8efac5bbb8ce59a47f6652120221008bdce60d43916e35db9c8ee889ba2f85acd2a98fa0193cce0a7f9f9d9867aac1",

        (constantly :foo)
        "304602210087d7aad4dc2789b8f58f97f541f95fc150ffc7fad8e09093932c023b13330e1a022100b434f9403048a983f8dfbd9b92ad8e2dac1ec4b1934dec8c94f4165bf981e01c",

        "금조류(琴鳥類, lyrebird)는 오스트레일리아 남부에 사는 참새목의 한 부류로, 주변의 소리를 잘 따라한다. 거문고새라고도 한다."
        "I should fail",

        "コトドリ属（コトドリぞく、学名 Menura）はコトドリ上科コトドリ科 Menuridae に属する鳥の属の一つ。コトドリ科は単型である。"
        7,

        "ဂျူးလိယက်ဆီဇာ(ဘီစီ၁၀၀-၄၄)"
        "304402206བང་འབངས་མི་ཞིག་ལ་མba84011c961db733e28f40f2496e8ff1ba60fcbf942b609fd1a9a6971f22e5b02202987d7d6ad5c330c7fdacefe3351554c00f42b82b7ad513104de8caebae40fc8",

        "རོ་མའི་རང་དབང་འབངས་མི་ཞིག་ལ་མིང་གསུམ་ཡོད་དེ།"
        "304402200e4b0560c42e4d1e19ddc2541f5531f7614628e9d01503d730ebe38c182baee8702206b80868e3d67fec2a9d5a594edd6b4f0266044965fe41e7cc3bff65feb922b7c",
        ))))

(deftest sin-tests
  (testing "Reference sins are valid"
    (are [x] (bitauth/validate-sin x)
      "TfKAQBFY3FPixJGVp81TWbjMdv2ftnZ8CRL"
      "TfGVzWqwft6fFdLzy8vR7qFTT77N7aTqa4n"
      "Tf4Lo9zAU73ezP7LKc3njaK5pez7oVhzH2H"
      "Tf7EsXB155iZ1aMkxh5ZyUJ7rTAyaZ6CFeT"
      "TexcsXqvbqeVrfpHQur5HvBqqQqBWB9XEsD"
      "TfBZ3DacgxVbemggEXZtHxoNXgD5FWi2cLD"
      "TfFc5Rh5NFFY6EsGcY6xe6vSct2hCWzk25X"))

  (testing "Ill-formatted sins are invalid"
    (are [x] (not (bitauth/validate-sin x))
      7
      (constantly :foo)
      :bar
      ""
      "\"\""
      "/TfKAQBFY3FPixJGVp81TWbjMdv2ftnZ8CRL"
      "TfGVzWqwft6fFdLzyvR7qFTT77N7aTqa4n"
      "Tf4Lo9zAezP7LKc3njaK5pez7oVhzH2H"
      "%Tf7EsXB155iZ1aMkxh5ZyUJ7rTAyaZ6CFeT"
      "&TexcsXqvbqeVrfpHQur5HvBqqQqBWB9XEsD"
      "TfBZ3DacgxVbem&&ggEXZtHxoNXgD5FWi2cLD"
      "1111TfFc5NFFY6EsGcY6xe6vSct2hCWzk25X")))

(deftest full-test
  (testing "Can generate a private key, public key, and SIN"
    (let [{:keys [:priv :pub :sin]} (bitauth/generate-sin)]
      (is (= pub (bitauth/get-public-key-from-private-key priv)))
      (is (= sin (-> priv
                     bitauth/get-public-key-from-private-key
                     bitauth/get-sin-from-public-key)))
      (is (bitauth/validate-sin sin))
      (are [x] (bitauth/verify-signature pub x (bitauth/sign priv x))
        "trololololol"
        "TfKAQBFY3FPixJGVp81TWbjMdv2ftnZ8CRL"
        "TfGVzWqwft6fFdLzy8vR7qFTT77N7aTqa4n"
        "Tf4Lo9zAU73ezP7LKc3njaK5pez7oVhzH2H"
        "Tf7EsXB155iZ1aMkxh5ZyUJ7rTAyaZ6CFeT"
        "TexcsXqvbqeVrfpHQur5HvBqqQqBWB9XEsD"
        "TfBZ3DacgxVbemggEXZtHxoNXgD5FWi2cLD"
        "TfFc5Rh5NFFY6EsGcY6xe6vSct2hCWzk25X"))))

(comment (run-tests))
