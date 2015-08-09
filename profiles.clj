{:dev {:test-paths ["test"]
       :plugins [[com.cemerick/clojurescript.test "0.3.3"]]
       :dependencies [[compojure "1.4.0"]
                      [http-kit "2.1.19"]
                      [ring/ring-defaults "0.1.5"]]
       :cljsbuild
       {:builds {:bitauth
                 {:source-paths ["test"]
                  :notify-command ["phantomjs" :cljs.test/runner "target/js/bitauth.js"]
                  :test-commands {"unit-tests" ["phantomjs" :runner
                                                "window.literal_js_was_evaluated=true"
                                                "target/js/bitauth.js"]}
                  :compiler {:output-dir "target/js"
                             :source-map "target/js/bitauth.js.map"
                             :optimizations :whitespace
                             :pretty-print true}}}}}}
