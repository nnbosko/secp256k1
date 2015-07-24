(ns bitauth.core)

(defn get-public-key-from-private-key
  "Generate a public key from a private key"
  []
  )

(defn get-sin-from-public-key
  "Generate a SIN from a compressed public key"
  ^String [^String pub-key]
  )

(defn generate-sin
  "Generate a new private key, new public key, SIN and timestamp"
  []
  )

(defn sign
  "Sign some data with a private-key"
  ^String [^String data, ^String priv-key]
  )

(defn verify
  "Verifies the given ASN.1 encoded ECDSA signature against a hash (byte-array) using a specified public key."
  [input pub-key hex-signature]
  )

(defn verify-signature
  "Verifies that a string of data has been signed."
  [data pub-key hex-signature]
  )

(defn validate-sin
  "Verify that a SIN is valid"
  [sin]
  )
