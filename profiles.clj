;;; ****************************** NOTES ******************************
;;; Defines four profiles:
;;;
;;; - :shared
;;; - :dev
;;; - :simple
;;; - :advanced
;;;
;;; the :dev, :simple and :advanced profiles are composite profiles,
;;; meaning that they share the content of :shared profile.
;;; *******************************************************************

{:shared {:test-paths ["test"]
          :plugins [[com.cemerick/clojurescript.test "0.3.3"]]
          :cljsbuild
          {:builds {:bitauth
                    {:source-paths ["test"]
                     :notify-command ["phantomjs"
                                      :cljs.test/runner "target/js/bitauth.js"]
                     :compiler {:output-dir "target/js"
                                :source-map "target/js/bitauth.js.map"
                                :optimizations :whitespace
                                :pretty-print true}}}}}

 :dev [:shared
       {:dependencies [[com.cemerick/piggieback "0.2.1"]
                       [org.clojure/tools.nrepl "0.2.10"]]
        :repl-options {:nrepl-middleware [cemerick.piggieback/wrap-cljs-repl]}
        :injections [(require '[cljs.repl.rhino] '[cemerick.piggieback])
                     (defn cljs-repl [] (cemerick.piggieback/cljs-repl (cljs.repl.rhino/repl-env)))]}]

 ;; simple profile.
 :simple [:shared
          {:cljsbuild
           {:builds {:bitauth
                     {:compiler {:optimizations :simple
                                 :pretty-print false}}}}}]
 ;; advanced profile
 :advanced [:shared
            {:cljsbuild
             {:builds {:bitauth
                       {:compiler {:optimizations :advanced
                                   :pretty-print false}}}}}]}
