(ns bitauth.middleware
  "Middleware for checking that requests conform to the bitauth protocol"
  (:require [bitauth.core :as bitauth]
            [clojure.walk :refer [keywordize-keys]]
            [ring.util.response :refer [response status]])
  (:import java.io.ByteArrayInputStream))

(defn wrap-bitauth
  "Wrap a handler so that headers of requests are checked to see if they conform to the bitauth protocol before forwarding with added :sin identification"
  [handler]
  (fn [request]
    (let [{:keys [:x-identity :x-signature :host]}
          (-> request :headers keywordize-keys)
          body (when (request :body) (slurp (request :body)))
          full-url (str (-> request :scheme name) "://" host (request :uri))
          data (str full-url body)]
      (if (bitauth/verify-signature x-identity data x-signature)
        (-> request
            (assoc :body (when body (-> body .getBytes ByteArrayInputStream.)))
            (assoc :sin (bitauth/get-sin-from-public-key x-identity))
            handler)
        (-> (response "Access Denied") (status 403))))))
