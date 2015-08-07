(defproject bitauth "0.0.1-SNAPSHOT"
  :license {:name "MIT"
            :url "http://opensource.org/licenses/MIT"
            :distribution :repo}
  :description "A Clojure/ClojureScript port of BitPay's bitauth authentical protocol"
  :url "https://github.com/xcthulhu/clj-bitauth"
  :min-lein-version "2.3.4"
  :source-paths ["src/clj" "src/cljs"]
  :dependencies [[org.clojure/clojure "1.7.0"]
                 [org.clojure/clojurescript "1.7.48"]
                 [com.madgag.spongycastle/core "1.52.0.0"]
                 [base58 "0.1.0"]]
  :node-dependencies [[bitauth "0.2.1"]
                      [uglify-js "2.4.24"]
                      [browserify "11.0.1"]]
  :plugins [[lein-cljsbuild "1.0.6"]
            [lein-npm "0.5.0"]
            [lein-shell "0.4.1"]]
  :hooks [leiningen.cljsbuild]
  :prep-tasks [["shell" "./scripts/install_bitpay_bitauth.sh"] "javac" "compile"]
  :clean-targets ^{:protect false} ["target/" "dist/" "lib/" "node_modules/" "resources/bitpay/"]
  :cljsbuild
  {:builds {:bitauth
            {:source-paths ["src/cljs" "dist"]
             :compiler
             {:output-to "target/js/bitauth.js"
              :optimizations :advanced
              :pretty-print false
              :foreign-libs
              [{:file "bitpay/bitauth.js"
                :file-min "bitpay/bitauth.min.js"
                :provides ["bitpay.bitauth"]}]}}}}
  :scm {:name "git"
        :url "https://github.com/xcthulhu/clj-bitauth.git"}
  :pom-addition [:developers [:developer
                              [:id "xcthulhu"]
                              [:name "Matthew Wampler-Doty"]]]
  :target-path "target")
