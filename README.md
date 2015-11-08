# BitAuth (in Clojure(Script))

[![Clojars Project](http://clojars.org/bitauth/latest-version.svg)](http://clojars.org/bitauth)

This is a Clojure(Script) port of BitPay's *BitAuth* protocol: [https://github.com/bitpay/bitauth](https://github.com/bitpay/bitauth)

The goals of this project are as follows:

✅ Provide a 100% API compatible Clojure implementation of BitPay's BitAuth <br/>
✅ Wrap BitPay's BitAuth [npm module](https://www.npmjs.com/package/bitauth) in ClojureScript (well, their derived browser bundle anyway), replete isomorphic Clojure ⇔ ClojureScript compatibility testing <br/>
✅ Provide [compojure](https://github.com/weavejester/compojure) middleware for checking BitAuth headers that is compatible with BitPay's [middleware for express.js](https://github.com/bitpay/bitauth/blob/master/lib/middleware/bitauth.js)<br/>
✅Expose a Java interface to our core library so baristas can use our efforts too

## Installation

Simply include in your `project.clj` file:

```clojure
:dependencies [[bitauth "0.0.4"]]
```

(or whatever is the latest version according to clojars...)

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
