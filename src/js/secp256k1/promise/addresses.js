/**
 * @fileoverview Asynchronous BitCoin addresses via `crypto.subtle`
 */

goog.provide('secp256k1.promise.addresses');
goog.require('goog.asserts');
goog.require('goog.math.Integer');
goog.require('secp256k1.Promise');
goog.require('secp256k1.promise.hashes');
goog.require('secp256k1.sjcl.codec.bytes');
goog.require('secp256k1.sjcl.codec.hex');
goog.require('secp256k1.sjcl.ecc.ECPoint');
goog.require('secp256k1.sjcl.hash.Ripemd160');


var Promise = secp256k1.Promise;

/**
 * Compute the BitCoin address for an elliptic curve point as an array of bytes.
 * @param {secp256k1.sjcl.ecc.ECPoint} data
 * @param {number=0x00} version A byte indicating the version
 * @returns {Promise<Array<number>>} A promise containing the BitCoin address as an array of bytes
 */
secp256k1.promise.addresses.bitcoinAddressBytes = function (data, version) {
    if (typeof version === "undefined") {
        version = 0x00;
    }
    goog.asserts.assert(secp256k1.sjcl.codec.bytes.isByte(version), "Version must be a byte");
    return secp256k1.promise.hashes.sha256([0x04].concat(
        secp256k1.sjcl.codec.bytes.fromBits(
            data.x.toBits(data.curve.field.exponent).concat(
                data.y.toBits(data.curve.field.exponent)))))
        .then(function (data) {
            var h = new secp256k1.sjcl.hash.Ripemd160();
            h.update(data);
            return h.digest();
        }).then(function (hash) {
            hash.unshift(version);
            return new Promise(function (resolve) {
                return secp256k1.promise.hashes.sha256(hash)
                    .then(secp256k1.promise.hashes.sha256)
                    .then(function (checksum_data) {
                        return resolve(hash.concat(checksum_data.slice(0, 4)));
                    });
            });
        });
};

/**
 * @type {!goog.math.Integer}
 * @const
 */
var fiftyEight = goog.math.Integer.fromInt(58);
/**
 * @type {!string}
 * @const
 */
var baseFiftyEightChars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/**
 * Convert a byte array into a Base 58 encoded string.
 * @param {Array<number>} data
 * @returns {string}
 */
function bytesToBase58(data) {
    goog.asserts.assert(
        secp256k1.sjcl.codec.bytes.isByteArrayLike(data),
        "Data must be byte array-like");
    var out = [];
    var zeros = -1;
    while (data[++zeros] === 0) {
    }
    var n = new goog.math.Integer.fromString(
        secp256k1.sjcl.codec.hex.fromBits(secp256k1.sjcl.codec.bytes.toBits(data)), 16);
    while (!n.isZero()) {
        out.unshift(baseFiftyEightChars[n.modulo(fiftyEight).toInt()]);
        n = n.divide(fiftyEight);
    }
    while (zeros-- != 0) {
        out.unshift(baseFiftyEightChars[0]);
    }
    return out.join("");
}

/**
 * Compute the BitCoin address for an elliptic curve point as an string as a Base58 encoded string.
 * @param {Array<number>|secp256k1.sjcl.ecc.ECPoint} data
 * @param {number=0x00} version A byte indicating the version
 * @returns {Promise<String>} A promise containing the BitCoin address as an array of bytes
 */
secp256k1.promise.addresses.bitcoinAddress = function (data, version) {
    if (typeof version === "undefined") {
        version = 0x00;
    }
    return secp256k1.promise.addresses.bitcoinAddressBytes(data, version).then(bytesToBase58);
};