/**
 * @fileoverview If native promises exist, make use of them.  Otherwise, fall back to polyfill.
 */

goog.provide('secp256k1.Promise');
goog.require('secp256k1.polyfill.Promise');


secp256k1.Promise = typeof window === "object" && typeof window.Promise === "function" ?
    window.Promise :
    secp256k1.polyfill.Promise;