(defproject bitauth "0.1.4"
  :license {:name "MIT"
            :url "http://opensource.org/licenses/MIT"
            :distribution :repo}
  :description "A Clojure(Script) port of BitPay's BitAuth authentical protocol"
  :url "https://github.com/Sepia-Officinalis/clj-bitauth"
  :min-lein-version "2.3.4"
  :jar-exclusions [#"\.DS_Store"]
  :source-paths ["src/clj" "src/cljs" "src/cljc"]
  :test-paths ["test"]
  :repositories [["jitpack" "https://jitpack.io"]]
  :dependencies [[com.github.Sepia-Officinalis/sjcl-cljs "0.1.9"]
                 [com.madgag.spongycastle/core "1.54.0.0"]
                 [org.clojure/clojure "1.9.0-alpha10"]
                 [org.clojure/clojurescript "1.9.93"]
                 [prismatic/schema "1.1.3"]
                 [ring/ring-core "1.5.0"]]


  :clean-targets ^{:protect false}
  [:target-path
   "dev-resources/public/js/compiled/"
   "out/"]

  ;; See profiles.clj for more details
  :profiles {:dev [~(if (= (System/getProperty "os.name") "Mac OS X")
                      :profiles/osx
                      :profiles/linux)
                   :profiles/dev]}

  ;; figwheel and devcards need this here
  :cljsbuild
  {:builds
   [{:id "devcards"
     :source-paths ["src/cljs" "src/cljc" "test"]
     :figwheel {:devcards true}
     :compiler
     {:main "bitauth.devcards"
      :asset-path "js/compiled/devcards_out"
      :output-to "dev-resources/public/js/compiled/bitauth_devcards.js"
      :output-dir "dev-resources/public/js/compiled/devcards_out"
      :source-map-timestamp true}}]}

  :scm
  {:name "git"
   :url "https://github.com/Sepia-Officinalis/clj-bitauth.git"}

  :pom-addition [:developers [:developer
                              [:id "xcthulhu"]
                              [:name "Matthew Wampler-Doty"]]])
