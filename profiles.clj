{:dev {:test-paths ["test"]
       :plugins [[com.cemerick/clojurescript.test "0.3.3"]]
       :cljsbuild
       {:builds {:bitauth
                 {:source-paths ["test"]
                  :notify-command ["phantomjs"
                                   :cljs.test/runner "target/js/bitauth.js"]
                  :compiler {:output-dir "target/js"
                             :source-map "target/js/bitauth.js.map"
                             :optimizations :whitespace
                             :pretty-print true}}}}}}
