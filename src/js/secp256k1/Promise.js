/**
 * @fileoverview If native promises exist, make use of them.  Otherwise, fall back to polyfill.
 */

goog.provide('secp256k1.Promise');
goog.require('secp256k1.polyfill.Promise');

// TODO: Make sure that Safari is really using native promises in advanced compilation, because I don't believe it.

/**
 * @const
 * @type {boolean}
 */
var nativePromise = typeof Promise === "function";

/**
 * Promise/A+ with fallback to a polyfill
 * @param {Function} fn Function to run over result when the promise is resolved
 * @constructor
 * @struct
 * @final
 */
secp256k1.Promise = nativePromise ? Promise : secp256k1.polyfill.Promise;

/**
 * @param {Array<Function|secp256k1.Promise>} arr
 * @returns {secp256k1.polyfill.Promise}
 */
secp256k1.Promise.all = nativePromise && typeof Promise['all'] === "function" ?
    Promise['all'] : secp256k1.polyfill.Promise.all;

/**
 * @param {*} value
 * @returns {secp256k1.Promise}
 */
secp256k1.Promise.resolve = nativePromise && typeof Promise['resolve'] === "function" ?
    Promise['resolve'] : secp256k1.polyfill.Promise.resolve;

/**
 * @param {*} value
 * @returns {secp256k1.Promise}
 */
secp256k1.Promise.reject = nativePromise && typeof Promise['reject'] === "function" ?
    Promise['reject'] : secp256k1.polyfill.Promise.reject;

/**
 * @param {Array<secp256k1.Promise>} values
 * @returns {secp256k1.Promise}
 */
secp256k1.Promise.race = nativePromise && typeof Promise['race'] === "function" ?
    Promise['race'] : secp256k1.polyfill.Promise.race;