# BitAuth (in Clojure(Script))

[![Build Status](https://travis-ci.org/Sepia-Officinalis/clj-bitauth.svg)](https://travis-ci.org/Sepia-Officinalis/clj-bitauth)

## Installation

Simply include in your `project.clj` file:

```
:repositories [["jitpack" "https://jitpack.io"]]
:dependencies [[com.github.Sepia-Officinalis/clj-bitauth "0.1.1"]]
```

## Info

This is a Clojure(Script) port of BitPay's *BitAuth* protocol: [https://github.com/bitpay/bitauth](https://github.com/bitpay/bitauth)

The goals of this project are as follows:

✅ Provide a 100% API compatible Clojure implementation of BitPay's BitAuth <br/>
✅ Isomorphic Clojure ⇔ ClojureScript compatibility testing <br/>
✅ Support advanced compilation under ClojureScript

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
