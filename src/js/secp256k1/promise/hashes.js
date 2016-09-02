/**
 * @fileoverview Asynchronous hashes via `crypto.subtle`
 *
 * This file provides an API for accessing built-in hashing functions via `crypto.subtle`
 *
 * Hashing functions return `Promise`s, either built-in or `goog.Promise` polyfills if built-in implementations
 * are not available.
 *
 * If `crypto.subtle` is not available, this code falls back on synchronous implementations of hashing functions.
 */

goog.provide('secp256k1.promise.hashes');
goog.require('secp256k1.Promise');
goog.require('goog.array');
goog.require('goog.crypt');
goog.require('secp256k1.hashes');

//noinspection JSUnresolvedVariable
var Promise = typeof window === "object" && typeof window.Promise === "function" ? window.Promise : secp256k1.Promise,
    crypto = typeof window === "object" ?
        (typeof window.crypto !== "undefined" ? window.crypto :
            (typeof window.msCrypto !== "undefined" ? window.msCrypto : undefined)) : undefined,
    subtleCrypto = typeof crypto === "object" ?
        (typeof crypto.subtle === "object" ? crypto.subtle :
            (typeof crypto.webkitSubtle === "object" ? crypto.webkitSubtle : undefined)) : undefined;

/**
 * Take the SHA256 hash of an array of bytes.
 * @param {Array<number>|Uint8Array|string} data An array of bytes to be hashed
 * @returns {Promise<Array<number>>} A promise containing the hashed result as an array of bytes.
 */
secp256k1.promise.hashes.sha256 = function (data) {
    if (typeof subtleCrypto !== "undefined") {
        data = typeof data === "string" ? goog.crypt.stringToUtf8ByteArray(data) : data;
        var buffer = new ArrayBuffer(data.length);
        (new Uint8Array(buffer)).set(new Uint8Array(data));
        return subtleCrypto.digest("SHA-256", buffer).then(
            function (outputBuffer) {
                //noinspection JSCheckFunctionSignatures
                return goog.array.toArray(new Uint8Array(outputBuffer));
            });
    } else {
        return new Promise(function (resolve) {
            return resolve(secp256k1.hashes.sha256(data));
        });
    }
};