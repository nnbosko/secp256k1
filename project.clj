(defproject bitauth "0.1.0"
  :license {:name "MIT"
            :url "http://opensource.org/licenses/MIT"
            :distribution :repo}
  :description "A Clojure(Script) port of BitPay's BitAuth authentical protocol"
  :url "https://github.com/xcthulhu/clj-bitauth"
  :min-lein-version "2.3.4"
  :jar-exclusions [#"\.DS_Store"]
  :source-paths ["src/clj" "src/cljs" "src/cljc"]
  :repositories [["jitpack" "https://jitpack.io"]]
  :dependencies [[base58 "0.1.0"]
                 [com.github.xcthulhu/bitauth-cljs "0.3.2-0"]
                 [com.madgag.spongycastle/core "1.52.0.0"]
                 [org.clojure/clojure "1.8.0"]
                 [org.clojure/clojurescript "1.8.34"]
                 [prismatic/schema "1.0.1"]
                 [ring/ring-core "1.4.0"]]

  :profiles {:uberjar {:aot :all}
             :dev {:test-paths ["test"]
                   :dependencies [[compojure "1.4.0"]
                                  [http-kit "2.1.19"]
                                  [ring/ring-defaults "0.1.5"]]
                   :plugins [[lein-npm "0.6.2"]
                             [lein-cljsbuild "1.1.2"
                              :exclusions
                              [[org.apache.commons/commons-compress]
                               [org.clojure/clojure]]]
                             [lein-doo "0.1.6"]]
                   :npm {:dependencies [[slimerjs "0.9.6"
                                         phantomjs-prebuilt "2.1.5"
                                         karma-cljs-test "0.1.0"
                                         karma-firefox-launcher "0.1.7"
                                         karma-chrome-launcher "0.2.2"
                                         karma "0.13.22"]]}
                   :doo {:paths {:slimer    "./node_modules/.bin/slimerjs"
                                 :phantomjs "./node_modules/.bin/phantomjs"}
                         :alias {:browsers [:chrome :firefox]
                                 :all      [:browsers :headless]}}
                   :cljsbuild {:builds
                               [{:id           "test"
                                 :source-paths ["src/cljs" "src/cljc" "test"]
                                 :compiler     {:output-to     "target/js/compiled/testable.js"
                                                :main          "bitauth.test-runner"
                                                :optimizations :none}}
                                {:id           "test-advanced"
                                 :source-paths ["src/cljs" "src/cljc" "test"]
                                 :compiler     {:output-to     "target/js/compiled/testable.min.js"
                                                :main          "chromatophore.doo.runner"
                                                :optimizations :advanced
                                                :pretty-print  false}}]
                               }}}
  :scm            {:name "git"
                   :url "https://github.com/Sepia-Officinalis/clj-bitauth.git"}
  :pom-addition [:developers [:developer
                              [:id "xcthulhu"]
                              [:name "Matthew Wampler-Doty"]]]
  :target-path  "target"
  :aliases      {"test-advanced"       ["do"
                                        ;;"clean,"
                                        ;;"npm" "install,"
                                        ;;"test,"
                                        "doo" "phantom" "test" "once,"
                                        ;;"doo" "all" "test-advanced" "once,"
                                        ]
                 "advanced-test"       ["test-advanced"]
                 "deep-clean"          ["do"
                                        "shell" "rm" "-rf" "figwheel_server.log" "node_modules,"
                                        "clean"]})
