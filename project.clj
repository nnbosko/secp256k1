(defproject bitauth "0.1.0"
  :license {:name "MIT"
            :url "http://opensource.org/licenses/MIT"
            :distribution :repo}
  :description "A Clojure(Script) port of BitPay's BitAuth authentical protocol"
  :url "https://github.com/xcthulhu/clj-bitauth"
  :min-lein-version "2.3.4"
  :jar-exclusions [#"\.DS_Store"]
  :source-paths ["src/clj" "src/cljs" "src/cljc"]
  :test-paths ["test"]
  :repositories [["jitpack" "https://jitpack.io"]]
  :dependencies [[com.github.xcthulhu/sjcl-cljs "0.1.9"]
                 [com.madgag.spongycastle/core "1.54.0.0"]
                 [org.clojure/clojure "1.8.0"]
                 [org.clojure/clojurescript "1.8.51"]
                 [prismatic/schema "1.1.1"]
                 [ring/ring-core "1.4.0"]]

  :profiles {:uberjar {:aot :all}
             :dev {:dependencies [[compojure "1.5.0"]
                                  [http-kit "2.1.19"]
                                  [ring/ring-defaults "0.2.0"]
                                  [doo "0.1.6"]
                                  [devcards "0.2.1-6"]]
                   :plugins [[lein-npm "0.6.2"]
                             [lein-shell "0.5.0"]
                             [lein-figwheel "0.5.2"]
                             [lein-cljsbuild "1.1.2"
                              :exclusions
                              [[org.apache.commons/commons-compress]
                               [org.clojure/clojure]]]
                             [lein-doo "0.1.6"]]}}

  :npm {:dependencies [[slimerjs "0.9.6"
                        phantomjs-prebuilt "2.1.5"
                        karma-cljs-test "0.1.0"
                        karma-firefox-launcher "0.1.7"
                        karma-chrome-launcher "0.2.2"
                        karma "0.13.22"]]}

  :clean-targets ^{:protect false} [:target-path
                                    "dev-resources/public/js/compiled/"
                                    "out/"]

  :doo {:paths {:slimer    "./node_modules/.bin/slimerjs"
                :phantomjs "./node_modules/.bin/phantomjs"
                :karma     "./node_modules/.bin/karma"}
        :alias {:browsers [:chrome :firefox]
                :all      [:browsers :headless]}}

  :cljsbuild {:builds
              [{:id           "devcards"
                :source-paths ["src/cljs" "src/cljc" "test"]
                :figwheel     {:devcards true}
                :compiler     {:main                 "bitauth.devcards"
                               :asset-path           "js/compiled/devcards_out"
                               :output-to            "dev-resources/public/js/compiled/bitauth_devcards.js"
                               :output-dir           "dev-resources/public/js/compiled/devcards_out"
                               :source-map-timestamp true}}
               {:id           "test"
                :source-paths ["src/cljs" "src/cljc" "test"]
                :compiler     {:output-to     "target/js/compiled/testable.js"
                               :main          "bitauth.test-runner"
                               :optimizations :none}}
               {:id           "test-advanced"
                :source-paths ["src/cljs" "src/cljc" "test"]
                :compiler     {:output-to     "target/js/compiled/testable.min.js"
                               :main          "bitauth.test-runner"
                               :optimizations :advanced
                               :pretty-print  false}}]}
  :scm          {:name "git"
                 :url "https://github.com/Sepia-Officinalis/clj-bitauth.git"}

  :pom-addition [:developers [:developer
                              [:id "xcthulhu"]
                              [:name "Matthew Wampler-Doty"]]]

  :aliases      {"test-advanced"       ["do"
                                        "clean,"
                                        "npm" "install,"
                                        "test,"
                                        "doo" "all" "test" "once,"
                                        "doo" "all" "test-advanced" "once,"]
                 "advanced-test"       ["test-advanced"]
                 "devcards"            ["do"
                                        "clean,"
                                        "figwheel,"]
                 "deep-clean"          ["do"
                                        "shell" "rm" "-rf" "figwheel_server.log" "node_modules,"
                                        "clean"]})
