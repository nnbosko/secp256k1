(defproject bitauth "0.0.3"
  :license {:name "MIT"
            :url "http://opensource.org/licenses/MIT"
            :distribution :repo}
  :description "A Clojure(Script) port of BitPay's BitAuth authentical protocol"
  :url "https://github.com/xcthulhu/clj-bitauth"
  :min-lein-version "2.3.4"
  :jar-exclusions [#"\.DS_Store"]
  :source-paths ["src/clj" "src/cljs"]
  :dependencies [[org.clojure/clojure "1.7.0"]
                 [org.clojure/clojurescript "1.7.48"]
                 [com.madgag.spongycastle/core "1.52.0.0"]
                 [ring/ring-core "1.4.0"]
                 [cljsjs/bitauth "0.2.1"]
                 [base58 "0.1.0"]]
  :plugins [[lein-cljsbuild "1.0.6"]
            [com.cemerick/clojurescript.test "0.3.3"]]
  :hooks [leiningen.cljsbuild]
  :cljsbuild {:builds [{:id "test"
                        :source-paths ["src/cljs" "test"]
                        :notify-command ["phantomjs" :cljs.test/runner "target/compiled/js/test.js"]
                        :compiler {:optimizations :whitespace
                                   :pretty-print true
                                   :output-to "target/compiled/js/test.js"
                                   :warnings {:single-segment-namespace false}}}]}
  :scm {:name "git"
        :url "https://github.com/xcthulhu/clj-bitauth.git"}
  :pom-addition [:developers [:developer
                              [:id "xcthulhu"]
                              [:name "Matthew Wampler-Doty"]]]
  :profiles {:dev {:test-paths ["test"]
                   :dependencies [[compojure "1.4.0"]
                                  [http-kit "2.1.19"]
                                  [ring/ring-defaults "0.1.5"]]}}
  :target-path "target")
