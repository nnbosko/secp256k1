# BitAuth (in Clojure(Script))

[![Build Status](https://travis-ci.org/Sepia-Officinalis/clj-bitauth.svg)](https://travis-ci.org/Sepia-Officinalis/clj-bitauth)

## Installation

Simply include in your `project.clj` file:

```
:repositories [["jitpack" "https://jitpack.io"]]
:dependencies [[com.github.Sepia-Officinalis/clj-bitauth "0.0.6"]]
```

## Info

This is a Clojure(Script) port of BitPay's *BitAuth* protocol: [https://github.com/bitpay/bitauth](https://github.com/bitpay/bitauth)

The goals of this project are as follows:

✅ Provide a 100% API compatible Clojure implementation of BitPay's BitAuth <br/>
✅ Wrap BitPay's BitAuth [npm module](https://www.npmjs.com/package/bitauth) in ClojureScript (well, their derived browser bundle anyway), replete isomorphic Clojure ⇔ ClojureScript compatibility testing <br/>
✅ Provide [compojure](https://github.com/weavejester/compojure) middleware for checking BitAuth headers that is compatible with BitPay's [middleware for express.js](https://github.com/bitpay/bitauth/blob/master/lib/middleware/bitauth.js)<br/>

## Testing

Clojure:

```bash
lein test
```

ClojureScript:

```bash
# test continuously
lein do clean, cljsbuild auto test
```

## Deploying

```bash
lein deploy clojars
```
