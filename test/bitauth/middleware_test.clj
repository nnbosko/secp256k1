(ns bitauth.middleware-test
  (:require [bitauth.core :as bitauth]
            [bitauth.middleware :refer :all]
            [clojure.test :refer :all]
            [compojure.core :refer [GET POST defroutes]]
            [compojure.handler :refer [site]]
            [org.httpkit.client :as http]
            [org.httpkit.server :refer [run-server]]))

(defroutes app
  (GET "/" [] "It is dangerous to go alone! Take this!")
  (POST "/echo" {body :body} (slurp body))
  ;; wrap-bitauth should add a sin field to the request
  ;; this path tests this
  (GET "/sin" {sin :sin} sin))

;; Get a random free port
(defonce port
  (with-open [socket-server (new java.net.ServerSocket 0)]
    (.getLocalPort socket-server)))

(use-fixtures :once
  (fn [f]
    (let [server (run-server (-> app wrap-bitauth site) {:port port})]
      (try (f) (finally (server))))))

(deftest get-root
  (testing "Sad path for GETting /"
    (let [url (str "http://0.0.0.0:" port "/")
          {:keys [:status :body] :as resp} @(http/get url)]
      (is (= "Access Denied" body))
      (is (= 403 status))))

  (testing "Happy path for GETting /"
    (let [{:keys [:priv :pub]} (bitauth/generate-sin)
          url (str "http://0.0.0.0:" port "/")
          options {:headers {"x-identity" pub
                             "x-signature" (bitauth/sign url priv)}}
          {:keys [:status :body] :as resp} @(http/get url options)]
      (is (= "It is dangerous to go alone! Take this!" body))
      (is (= 200 status)))))

(deftest post-echo
  (testing "Sad path for POSTing to /echo"
    (let [url (str "http://0.0.0.0:" port "/echo")
          {:keys [:status :body] :as resp} @(http/post url {:body "foo"})]
      (is (= "Access Denied" body))
      (is (= 403 status))))

  (testing "Happy path for POSTing to /echo"
    (let [{:keys [:priv :pub]} (bitauth/generate-sin)
          url (str "http://0.0.0.0:" port "/echo")
          data "foo"
          options {:headers {"x-identity" pub
                             "x-signature" (bitauth/sign (str url data) priv)}
                   :body data}
          {:keys [:status :body] :as resp} @(http/post url options)]
      (is (= "foo" body))
      (is (= 200 status)))))

(deftest get-sin
  (testing "Can GET /sin (when following authentication protocol)"
    (let [{:keys [:priv :pub :sin]} (bitauth/generate-sin)
          url (str "http://0.0.0.0:" port "/sin")
          options {:headers {"x-identity" pub
                             "x-signature" (bitauth/sign url priv)}}
          {:keys [:status :body] :as resp} @(http/get url options)]
      (is (= sin body))
      (is (= 200 status)))))

(comment (run-tests))
