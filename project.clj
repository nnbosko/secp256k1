(defproject bitauth "0.1.0-SNAPSHOT"
  :license {:name "MIT"
            :url "http://opensource.org/licenses/MIT"}
  :description "A Clojure/ClojureScript port of BitPay's bitauth authentical protocol"
  :url "https://github.com/xcthulhu/clj-bitauth"
  :dependencies [[org.clojure/clojure "1.7.0"]
                 [org.bouncycastle/bcprov-jdk15on "1.52"]
                 [base58 "0.1.0"]
                 [com.cemerick/clojurescript.test "0.3.3"]
                 [org.clojure/clojurescript "0.0-3308"
                  :classifier "aot"
                  :exclusion [org.clojure/data.json]]
                 [org.clojure/data.json "0.2.6"
                  :classifier "aot"]]
  :jvm-opts ^:replace ["-Xmx1g" "-server"]

  :node-dependencies [[source-map-support "0.3.2"]
                      [bitauth "0.2.1"]
                      [uglify-js "2.4.24"]
                      [browserify "11.0.1"]]

  :plugins [[lein-npm "0.5.0"]
            [lein-cljsbuild "1.0.6"]]

  :clean-targets ["target/" "dist/" "lib/" "node_modules/"]
  :cljsbuild {:builds {:dev
                       {:source-paths ["src-cljs" "dist"]
                        :compiler {:pretty-print true
                                   :output-to "target/js/bitauth.js"
                                   :optimizations :whitespace
                                   :foreign-libs
                                   [{:file "bitpay/bitauth.js"
                                     :provides ["bitpay.bitauth"]}]}}
                       :test
                       {:source-paths ["src-cljs" "dist" "test"]
                        :compiler {:output-to "target/js/unit-test.js"
                                   :optimizations :whitespace
                                   :pretty-print true
                                   :foreign-libs
                                   [{:file "bitpay/bitauth.js"
                                     :provides ["bitpay.bitauth"]}]}}}
              :test-commands
              {"phantomjs" ["phantomjs"
                            "phantom/unit-test.js"
                            "resources/private/html/unit-test.html"]}}

  :scm {:name "git"
        :url "https://github.com/xcthulhu/clj-bitauth.git"}

  :pom-addition [:developers [:developer
                              [:id "xcthulhu"]
                              [:name "Matthew Wampler-Doty"]]]
  :target-path "target")
