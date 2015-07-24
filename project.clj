(defproject bitauth "0.1.0-SNAPSHOT"
  :license {:name "MIT"
            :url "http://opensource.org/licenses/MIT"}
  :description "A Clojure/ClojureScript port of BitPay's bitauth authentical protocol"
  :url "https://github.com/bitpay/bitauth"
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
  :node-dependencies [[source-map-support "0.3.2"]]
  :plugins [[lein-npm "0.5.0"]
            [lein-cljsbuild "1.0.6"]]
  :jar-exclusions [#"js/.*\.js"]

  :cljsbuild {:builds {:dev
                       {:source-paths ["src/main/clojure"]
                        :compiler {:pretty-print true
                                   :output-to "target/js/bitauth.js"
                                   :optimizations :whitespace}}}}

  :profiles {:dev {:dependencies [[cljsbuild "1.0.6"]]
                   :hooks [leiningen.cljsbuild]}
             :test-cljs {:cljsbuild
                         {:builds
                          {:test {:source-paths ["test"]
                                  :notify-command ["phantomjs" "phantom/unit-test.js" "phantom/unit-test.html"]
                                  :compiler {:output-to "target/cljs-test/testable.js"
                                             :pretty-print true
                                             :optimizations :whitespace}}}}}

             :jar {:cljsbuild
                   {:builds
                    {:dev {:compiler
                           {:output-to "/tmp/bitauth/target/js/out/bitauth.js"
                            :output-dir "/tmp/bitauth/target/js/out"
                            :pretty-print false
                            :optimizations :advanced}}}}}

             :aot {:aliases {"check" ["do" "clean," "compile"]}
                   :hooks [leiningen.cljsbuild]
                   :target-path "/tmp/bitauth/target/%s"
                   :compile-path "/tmp/bitauth/target/classes"
                   :clean-targets ^{:protect false} ["/tmp/bitauth/target"]
                   :aot :all
                   :cljsbuild {:builds
                               {:dev {:compiler
                                      {:output-to "/tmp/bitauth/target/js/out/bitauth.js"
                                       :output-dir "/tmp/bitauth/target/js/out"
                                       :pretty-print false
                                       :optimizations :advanced}}}}}}

  :scm {:name "git"
        :url "https://github.com/xcthulhu/clj-bitauth.git"}
  :pom-addition [:developers [:developer
                              [:id "xcthulhu"]
                              [:name "Matthew Wampler-Doty"]]]
  :target-path "target")
