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
            And after he's been hooked I'll play the one that's on his heart"
        "☕️   ⓝ  🀤  ⎈  ∲"
        "इसकी दो प्रजातियाँ हैं सुपर्ब लायर बर्ड तथा अलबर्ट्स लायर बर्ड"
        "금조류(琴鳥類, lyrebird)는 오스트레일리아 남부에 사는 참새목의 한 부류로, 주변의 소리를 잘 따라한다. 거문고새라고도 한다."
        "コトドリ属（コトドリぞく、学名 Menura）はコトドリ上科コトドリ科 Menuridae に属する鳥の属の一つ。コトドリ科は単型である。"
        )))
  (testing "Reference signatures"
    (let [priv-key "8295702b2273896ae085c3caebb02985cab02038251e10b6f67a14340edb51b0"
          pub-key (bitauth/get-public-key-from-private-key priv-key)]
      (are [x y] (bitauth/verify-signature x pub-key y)
        "foo"  "30450220451cce92b56350ea747ad5fcf848a9cbed97277825d8be13c0fcf8eaf4e015fa0221008ff5310557e301630c59373d84664d1dd4eaaddefb7a896c60f25365dfb28f82",

        "baz" "304402202d6c14c8e0d9049aa9b0643c27c5b58c2aa75c318614d8344967a884e6a6370302201dd74af254a8eecaf5cb1dc9a16757b5fc4e0b1b6851f10035909fc0419c7779",

        "What a piece of work is a man! how noble in reason! how infinite in faculty! in form and moving how express and admirable! in action how like an angel! in apprehension how like a god!"
        "3045022100a98d807592e2c77f3f4e16f45f540e9f83093db08ab0a61c35ad08f0a016ecea022067631d3ea1c646553bb4242835f7d54efcc0e7e84c1e61ab0f01be8b1104bbb4",

        "☕️   ⓝ  🀤  ⎈  ∲"
        "3045022100cfd45a68c1ed6b3f24514b024ba10906355305be8b3acba33ed92e420f8c307d022051cdea572b7869c2dfafd0fbfe7823c99a3c67621b6adeb856abe24d1575e199",

        "इसकी दो प्रजातियाँ हैं सुपर्ब लायर बर्ड तथा अलबर्ट्स लायर बर्ड"
        "3045022079151babc06074279e3c322259e85c166409b5dbad04343573d596aa9da0c1d7022100b132eb81e92362772e6507d8cba7bd710c8764f9c6bf8b6852143c6bf77d0b45",

        "금조류(琴鳥類, lyrebird)는 오스트레일리아 남부에 사는 참새목의 한 부류로, 주변의 소리를 잘 따라한다. 거문고새라고도 한다."
        "304502202ce7e7ae440bde0bed0c647bdbcce501320109413b3d77dbcc117282264797640221008d0570f65598b234506a83f9958b80535f6cd87a664c2c7f6942ea90e736ffcc",

        "コトドリ属（コトドリぞく、学名 Menura）はコトドリ上科コトドリ科 Menuridae に属する鳥の属の一つ。コトドリ科は単型である。"
        "304502203b287b4e720016aff0144a35b2c5d8738da939238b7481348a2744a8478740370221009e3349f5a99c84359f1cee315a8fb520c317b5ed139c302b82de52c8b358c778",
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
