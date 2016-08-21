# Secp256k1
*A Clojure(Script) Crytography Library*

[![Build Status](https://travis-ci.org/Sepia-Officinalis/secp256k1.svg)](https://travis-ci.org/Sepia-Officinalis/secp256k1)

## Installation

Simply include in your `project.clj` file:

```
:repositories [["jitpack" "https://jitpack.io"]]
:dependencies [[com.github.Sepia-Officinalis/secp256k1 "1.0.0"]]
```

## Info

This is a library implements elliptic curve cryptography for [secp256k1](https://en.bitcoin.it/wiki/Secp256k1), the elliptic curve used by BitCoin.

The goals of this project are as follows:

✅ Isomorphic Clojure ⇔ ClojureScript compatibility testing<br/>
✅ Support advanced compilation under ClojureScript<br/>
❌ Allow for the user to access browser native cryptographic primitives in [`crypto.subtle`](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto) via Clojure's own `core.async`.<br/>
❌ Wrap the libsecp256k1 JNI provided by [BitCoin Core](https://github.com/bitcoin-core/secp256k1/tree/master/src/java)<br/>
❌ [Diffie-Helman](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange) shared secrets<br/>
❌ Implement BitCoin's [_recovery id_](https://github.com/bitcoin-core/secp256k1/blob/269d4227038b188128353235a272a8f030c307b1/include/secp256k1_recovery.h#L28) for compressed signatures<br/>

## Testing

Testing is carried out at the command line

Clojure:

    lein test


ClojureScript:


    # test continuously
    lein do clean, cljsbuild auto test

