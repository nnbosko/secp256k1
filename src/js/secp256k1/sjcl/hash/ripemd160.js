// SJCL is open. You can use, modify and redistribute it under a BSD
// license or under the GNU GPL, version 2.0.
//
// ---------------------------------------------------------------------
//
// http://opensource.org/licenses/BSD-2-Clause
//
// Copyright (c) 2009-2015, Emily Stark, Mike Hamburg and Dan Boneh at
// Stanford University. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
// 1. Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in the
// documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
// TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
// PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
// TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

/** 
 * @fileoverview Javascript RIPEMD-160 implementation.
 *
 * @author Artem S Vybornov <vybornov@gmail.com>
 * @author Matthew Wampler-Doty
 */

goog.provide('secp256k1.sjcl.hash.ripemd160');
goog.require('secp256k1.sjcl.bitArray');
goog.require('secp256k1.sjcl.codec.bytes');

/**
 * Context for a RIPEMD-160 operation in progress.
 * @constructor
 * @struct
 */
secp256k1.sjcl.hash.ripemd160 = function(hash) {
    /**
     * Holds the current values of accumulated A-E variables (MD buffer).
     * @type {!Array<number>}
     * @private
     */
    this._h = new Array(5);
    this.reset();
};

/**
 * Hash a string or an array of words.
 * @static
 * @param {Array<number>|String} data the data to hash.
 * @return {Array<number>} The hash value, an array of 5 big-endian words.
 */
secp256k1.sjcl.hash.ripemd160.hash = function(data) {
    return (new secp256k1.sjcl.hash.ripemd160()).update(data).digest();
};

/**
 * Swap the endianess of a 32 bit integer argument
 * @param {number} val Number to have endianness swapped.
 * @return {number} The swapped endianness.
 * @private
 */
function swap32(val) {
    return ((val & 0xFF) << 24) |
        ((val & 0xFF00) << 8) |
        ((val >> 8) & 0xFF00) |
        ((val >> 24) & 0xFF);
}

/**
 * Reset the hash state.
 * @return secp256k1.sjcl.hash.ripemd160
 */
secp256k1.sjcl.hash.ripemd160.prototype.reset = function() {
    this._h[0] = 0x67452301;
    this._h[1] = 0xefcdab89;
    this._h[2] = 0x98badcfe;
    this._h[3] = 0x10325476;
    this._h[4] = 0xc3d2e1f0;
    this._buffer = [];
    this._length = 0;
    return this;
};

/**
 * Update the hash state.
 * @param {Array<number>} data the data to hash.
 * @return secp256k1.sjcl.hash.ripemd160
 */
secp256k1.sjcl.hash.ripemd160.prototype.update = function(data) {
    data = secp256k1.sjcl.codec.bytes.toBits(data);
    this._buffer = secp256k1.sjcl.bitArray.concat(this._buffer, data);
    var i, b = this._buffer,
        ol = this._length,
        nl = ol + secp256k1.sjcl.bitArray.bitLength(data),
        words, w;
    this._length = nl;
    if (nl > 9007199254740991) {
        throw new Error("Cannot hash more than 2^53 - 1 bits");
    }
    for (i = 512 + ol - ((512 + ol) & 511); i <= nl; i += 512) {
        words = b.splice(0, 16);
        for (w = 0; w < 16; ++w) {
            words[w] = swap32(words[w]);
	}
        this._block(words);
    }

    return this;
};

/**
 * Complete hashing and output the hash value.
 * @return {Array<number>} The hash value, an array of 5 big-endian words.
 */
secp256k1.sjcl.hash.ripemd160.prototype.digest = function() {
    var b = secp256k1.sjcl.bitArray.concat(this._buffer, [secp256k1.sjcl.bitArray.partial(1, 1)]),
        l = (this._length + 1) % 512,
        z = (l > 448 ? 512 : 448) - l % 448,
        zp = z % 32,
        words, w;

    if (zp > 0) {
        b = secp256k1.sjcl.bitArray.concat(b, [secp256k1.sjcl.bitArray.partial(zp, 0)]);
    }
    for (; z >= 32; z -= 32) {
        b.push(0);
    }

    b.push(swap32(this._length | 0));
    b.push(swap32(Math.floor(this._length / 0x100000000)));

    while (b.length) {
        words = b.splice(0, 16);
        for (w = 0; w < 16; ++w)
            words[w] = swap32(words[w]);

        this._block(words);
    }

    var h = this._h.slice(0);
    this.reset();

    for (w = 0; w < 5; ++w)
        h[w] = swap32(h[w]);

    return secp256k1.sjcl.codec.bytes.fromBits(h);
};


function rotl (x, n) {
  return (x << n) | (x >>> (32 - n));
}

function fn1 (a, b, c, d, e, m, k, s) {
  return (rotl((a + (b ^ c ^ d) + m + k) | 0, s) + e) | 0;
}

function fn2 (a, b, c, d, e, m, k, s) {
  return (rotl((a + ((b & c) | ((~b) & d)) + m + k) | 0, s) + e) | 0;
}

function fn3 (a, b, c, d, e, m, k, s) {
  return (rotl((a + ((b | (~c)) ^ d) + m + k) | 0, s) + e) | 0;
}

function fn4 (a, b, c, d, e, m, k, s) {
  return (rotl((a + ((b & d) | (c & (~d))) + m + k) | 0, s) + e) | 0;
}

function fn5 (a, b, c, d, e, m, k, s) {
  return (rotl((a + (b ^ (c | (~d))) + m + k) | 0, s) + e) | 0;
}

/**
 * Run an iteration of the RIPEMD160 block hash.
 * @param {Array<number>} m Data to be hashed.
 * @private
 */
secp256k1.sjcl.hash.ripemd160.prototype._block = function (m) {

  var al = this._h[0];
  var bl = this._h[1];
  var cl = this._h[2];
  var dl = this._h[3];
  var el = this._h[4];

  // Mj = 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
  // K = 0x00000000
  // Sj = 11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8
  al = fn1(al, bl, cl, dl, el, m[0], 0x00000000, 11); cl = rotl(cl, 10);
  el = fn1(el, al, bl, cl, dl, m[1], 0x00000000, 14); bl = rotl(bl, 10);
  dl = fn1(dl, el, al, bl, cl, m[2], 0x00000000, 15); al = rotl(al, 10);
  cl = fn1(cl, dl, el, al, bl, m[3], 0x00000000, 12); el = rotl(el, 10);
  bl = fn1(bl, cl, dl, el, al, m[4], 0x00000000, 5); dl = rotl(dl, 10);
  al = fn1(al, bl, cl, dl, el, m[5], 0x00000000, 8); cl = rotl(cl, 10);
  el = fn1(el, al, bl, cl, dl, m[6], 0x00000000, 7); bl = rotl(bl, 10);
  dl = fn1(dl, el, al, bl, cl, m[7], 0x00000000, 9); al = rotl(al, 10);
  cl = fn1(cl, dl, el, al, bl, m[8], 0x00000000, 11); el = rotl(el, 10);
  bl = fn1(bl, cl, dl, el, al, m[9], 0x00000000, 13); dl = rotl(dl, 10);
  al = fn1(al, bl, cl, dl, el, m[10], 0x00000000, 14); cl = rotl(cl, 10);
  el = fn1(el, al, bl, cl, dl, m[11], 0x00000000, 15); bl = rotl(bl, 10);
  dl = fn1(dl, el, al, bl, cl, m[12], 0x00000000, 6); al = rotl(al, 10);
  cl = fn1(cl, dl, el, al, bl, m[13], 0x00000000, 7); el = rotl(el, 10);
  bl = fn1(bl, cl, dl, el, al, m[14], 0x00000000, 9); dl = rotl(dl, 10);
  al = fn1(al, bl, cl, dl, el, m[15], 0x00000000, 8); cl = rotl(cl, 10);

  // Mj = 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8
  // K = 0x5a827999
  // Sj = 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12
  el = fn2(el, al, bl, cl, dl, m[7], 0x5a827999, 7); bl = rotl(bl, 10);
  dl = fn2(dl, el, al, bl, cl, m[4], 0x5a827999, 6); al = rotl(al, 10);
  cl = fn2(cl, dl, el, al, bl, m[13], 0x5a827999, 8); el = rotl(el, 10);
  bl = fn2(bl, cl, dl, el, al, m[1], 0x5a827999, 13); dl = rotl(dl, 10);
  al = fn2(al, bl, cl, dl, el, m[10], 0x5a827999, 11); cl = rotl(cl, 10);
  el = fn2(el, al, bl, cl, dl, m[6], 0x5a827999, 9); bl = rotl(bl, 10);
  dl = fn2(dl, el, al, bl, cl, m[15], 0x5a827999, 7); al = rotl(al, 10);
  cl = fn2(cl, dl, el, al, bl, m[3], 0x5a827999, 15); el = rotl(el, 10);
  bl = fn2(bl, cl, dl, el, al, m[12], 0x5a827999, 7); dl = rotl(dl, 10);
  al = fn2(al, bl, cl, dl, el, m[0], 0x5a827999, 12); cl = rotl(cl, 10);
  el = fn2(el, al, bl, cl, dl, m[9], 0x5a827999, 15); bl = rotl(bl, 10);
  dl = fn2(dl, el, al, bl, cl, m[5], 0x5a827999, 9); al = rotl(al, 10);
  cl = fn2(cl, dl, el, al, bl, m[2], 0x5a827999, 11); el = rotl(el, 10);
  bl = fn2(bl, cl, dl, el, al, m[14], 0x5a827999, 7); dl = rotl(dl, 10);
  al = fn2(al, bl, cl, dl, el, m[11], 0x5a827999, 13); cl = rotl(cl, 10);
  el = fn2(el, al, bl, cl, dl, m[8], 0x5a827999, 12); bl = rotl(bl, 10);

  // Mj = 3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12
  // K = 0x6ed9eba1
  // Sj = 11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5
  dl = fn3(dl, el, al, bl, cl, m[3], 0x6ed9eba1, 11); al = rotl(al, 10);
  cl = fn3(cl, dl, el, al, bl, m[10], 0x6ed9eba1, 13); el = rotl(el, 10);
  bl = fn3(bl, cl, dl, el, al, m[14], 0x6ed9eba1, 6); dl = rotl(dl, 10);
  al = fn3(al, bl, cl, dl, el, m[4], 0x6ed9eba1, 7); cl = rotl(cl, 10);
  el = fn3(el, al, bl, cl, dl, m[9], 0x6ed9eba1, 14); bl = rotl(bl, 10);
  dl = fn3(dl, el, al, bl, cl, m[15], 0x6ed9eba1, 9); al = rotl(al, 10);
  cl = fn3(cl, dl, el, al, bl, m[8], 0x6ed9eba1, 13); el = rotl(el, 10);
  bl = fn3(bl, cl, dl, el, al, m[1], 0x6ed9eba1, 15); dl = rotl(dl, 10);
  al = fn3(al, bl, cl, dl, el, m[2], 0x6ed9eba1, 14); cl = rotl(cl, 10);
  el = fn3(el, al, bl, cl, dl, m[7], 0x6ed9eba1, 8); bl = rotl(bl, 10);
  dl = fn3(dl, el, al, bl, cl, m[0], 0x6ed9eba1, 13); al = rotl(al, 10);
  cl = fn3(cl, dl, el, al, bl, m[6], 0x6ed9eba1, 6); el = rotl(el, 10);
  bl = fn3(bl, cl, dl, el, al, m[13], 0x6ed9eba1, 5); dl = rotl(dl, 10);
  al = fn3(al, bl, cl, dl, el, m[11], 0x6ed9eba1, 12); cl = rotl(cl, 10);
  el = fn3(el, al, bl, cl, dl, m[5], 0x6ed9eba1, 7); bl = rotl(bl, 10);
  dl = fn3(dl, el, al, bl, cl, m[12], 0x6ed9eba1, 5); al = rotl(al, 10);

  // Mj = 1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2
  // K = 0x8f1bbcdc
  // Sj = 11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12
  cl = fn4(cl, dl, el, al, bl, m[1], 0x8f1bbcdc, 11); el = rotl(el, 10);
  bl = fn4(bl, cl, dl, el, al, m[9], 0x8f1bbcdc, 12); dl = rotl(dl, 10);
  al = fn4(al, bl, cl, dl, el, m[11], 0x8f1bbcdc, 14); cl = rotl(cl, 10);
  el = fn4(el, al, bl, cl, dl, m[10], 0x8f1bbcdc, 15); bl = rotl(bl, 10);
  dl = fn4(dl, el, al, bl, cl, m[0], 0x8f1bbcdc, 14); al = rotl(al, 10);
  cl = fn4(cl, dl, el, al, bl, m[8], 0x8f1bbcdc, 15); el = rotl(el, 10);
  bl = fn4(bl, cl, dl, el, al, m[12], 0x8f1bbcdc, 9); dl = rotl(dl, 10);
  al = fn4(al, bl, cl, dl, el, m[4], 0x8f1bbcdc, 8); cl = rotl(cl, 10);
  el = fn4(el, al, bl, cl, dl, m[13], 0x8f1bbcdc, 9); bl = rotl(bl, 10);
  dl = fn4(dl, el, al, bl, cl, m[3], 0x8f1bbcdc, 14); al = rotl(al, 10);
  cl = fn4(cl, dl, el, al, bl, m[7], 0x8f1bbcdc, 5); el = rotl(el, 10);
  bl = fn4(bl, cl, dl, el, al, m[15], 0x8f1bbcdc, 6); dl = rotl(dl, 10);
  al = fn4(al, bl, cl, dl, el, m[14], 0x8f1bbcdc, 8); cl = rotl(cl, 10);
  el = fn4(el, al, bl, cl, dl, m[5], 0x8f1bbcdc, 6); bl = rotl(bl, 10);
  dl = fn4(dl, el, al, bl, cl, m[6], 0x8f1bbcdc, 5); al = rotl(al, 10);
  cl = fn4(cl, dl, el, al, bl, m[2], 0x8f1bbcdc, 12); el = rotl(el, 10);

  // Mj = 4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13
  // K = 0xa953fd4e
  // Sj = 9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6
  bl = fn5(bl, cl, dl, el, al, m[4], 0xa953fd4e, 9); dl = rotl(dl, 10);
  al = fn5(al, bl, cl, dl, el, m[0], 0xa953fd4e, 15); cl = rotl(cl, 10);
  el = fn5(el, al, bl, cl, dl, m[5], 0xa953fd4e, 5); bl = rotl(bl, 10);
  dl = fn5(dl, el, al, bl, cl, m[9], 0xa953fd4e, 11); al = rotl(al, 10);
  cl = fn5(cl, dl, el, al, bl, m[7], 0xa953fd4e, 6); el = rotl(el, 10);
  bl = fn5(bl, cl, dl, el, al, m[12], 0xa953fd4e, 8); dl = rotl(dl, 10);
  al = fn5(al, bl, cl, dl, el, m[2], 0xa953fd4e, 13); cl = rotl(cl, 10);
  el = fn5(el, al, bl, cl, dl, m[10], 0xa953fd4e, 12); bl = rotl(bl, 10);
  dl = fn5(dl, el, al, bl, cl, m[14], 0xa953fd4e, 5); al = rotl(al, 10);
  cl = fn5(cl, dl, el, al, bl, m[1], 0xa953fd4e, 12); el = rotl(el, 10);
  bl = fn5(bl, cl, dl, el, al, m[3], 0xa953fd4e, 13); dl = rotl(dl, 10);
  al = fn5(al, bl, cl, dl, el, m[8], 0xa953fd4e, 14); cl = rotl(cl, 10);
  el = fn5(el, al, bl, cl, dl, m[11], 0xa953fd4e, 11); bl = rotl(bl, 10);
  dl = fn5(dl, el, al, bl, cl, m[6], 0xa953fd4e, 8); al = rotl(al, 10);
  cl = fn5(cl, dl, el, al, bl, m[15], 0xa953fd4e, 5); el = rotl(el, 10);
  bl = fn5(bl, cl, dl, el, al, m[13], 0xa953fd4e, 6); dl = rotl(dl, 10);

  var ar = this._h[0];
  var br = this._h[1];
  var cr = this._h[2];
  var dr = this._h[3];
  var er = this._h[4];

  // M'j = 5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12
  // K' = 0x50a28be6
  // S'j = 8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6
  ar = fn5(ar, br, cr, dr, er, m[5], 0x50a28be6, 8); cr = rotl(cr, 10);
  er = fn5(er, ar, br, cr, dr, m[14], 0x50a28be6, 9); br = rotl(br, 10);
  dr = fn5(dr, er, ar, br, cr, m[7], 0x50a28be6, 9); ar = rotl(ar, 10);
  cr = fn5(cr, dr, er, ar, br, m[0], 0x50a28be6, 11); er = rotl(er, 10);
  br = fn5(br, cr, dr, er, ar, m[9], 0x50a28be6, 13); dr = rotl(dr, 10);
  ar = fn5(ar, br, cr, dr, er, m[2], 0x50a28be6, 15); cr = rotl(cr, 10);
  er = fn5(er, ar, br, cr, dr, m[11], 0x50a28be6, 15); br = rotl(br, 10);
  dr = fn5(dr, er, ar, br, cr, m[4], 0x50a28be6, 5); ar = rotl(ar, 10);
  cr = fn5(cr, dr, er, ar, br, m[13], 0x50a28be6, 7); er = rotl(er, 10);
  br = fn5(br, cr, dr, er, ar, m[6], 0x50a28be6, 7); dr = rotl(dr, 10);
  ar = fn5(ar, br, cr, dr, er, m[15], 0x50a28be6, 8); cr = rotl(cr, 10);
  er = fn5(er, ar, br, cr, dr, m[8], 0x50a28be6, 11); br = rotl(br, 10);
  dr = fn5(dr, er, ar, br, cr, m[1], 0x50a28be6, 14); ar = rotl(ar, 10);
  cr = fn5(cr, dr, er, ar, br, m[10], 0x50a28be6, 14); er = rotl(er, 10);
  br = fn5(br, cr, dr, er, ar, m[3], 0x50a28be6, 12); dr = rotl(dr, 10);
  ar = fn5(ar, br, cr, dr, er, m[12], 0x50a28be6, 6); cr = rotl(cr, 10);

  // M'j = 6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2
  // K' = 0x5c4dd124
  // S'j = 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11
  er = fn4(er, ar, br, cr, dr, m[6], 0x5c4dd124, 9); br = rotl(br, 10);
  dr = fn4(dr, er, ar, br, cr, m[11], 0x5c4dd124, 13); ar = rotl(ar, 10);
  cr = fn4(cr, dr, er, ar, br, m[3], 0x5c4dd124, 15); er = rotl(er, 10);
  br = fn4(br, cr, dr, er, ar, m[7], 0x5c4dd124, 7); dr = rotl(dr, 10);
  ar = fn4(ar, br, cr, dr, er, m[0], 0x5c4dd124, 12); cr = rotl(cr, 10);
  er = fn4(er, ar, br, cr, dr, m[13], 0x5c4dd124, 8); br = rotl(br, 10);
  dr = fn4(dr, er, ar, br, cr, m[5], 0x5c4dd124, 9); ar = rotl(ar, 10);
  cr = fn4(cr, dr, er, ar, br, m[10], 0x5c4dd124, 11); er = rotl(er, 10);
  br = fn4(br, cr, dr, er, ar, m[14], 0x5c4dd124, 7); dr = rotl(dr, 10);
  ar = fn4(ar, br, cr, dr, er, m[15], 0x5c4dd124, 7); cr = rotl(cr, 10);
  er = fn4(er, ar, br, cr, dr, m[8], 0x5c4dd124, 12); br = rotl(br, 10);
  dr = fn4(dr, er, ar, br, cr, m[12], 0x5c4dd124, 7); ar = rotl(ar, 10);
  cr = fn4(cr, dr, er, ar, br, m[4], 0x5c4dd124, 6); er = rotl(er, 10);
  br = fn4(br, cr, dr, er, ar, m[9], 0x5c4dd124, 15); dr = rotl(dr, 10);
  ar = fn4(ar, br, cr, dr, er, m[1], 0x5c4dd124, 13); cr = rotl(cr, 10);
  er = fn4(er, ar, br, cr, dr, m[2], 0x5c4dd124, 11); br = rotl(br, 10);

  // M'j = 15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13
  // K' = 0x6d703ef3
  // S'j = 9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5
  dr = fn3(dr, er, ar, br, cr, m[15], 0x6d703ef3, 9); ar = rotl(ar, 10);
  cr = fn3(cr, dr, er, ar, br, m[5], 0x6d703ef3, 7); er = rotl(er, 10);
  br = fn3(br, cr, dr, er, ar, m[1], 0x6d703ef3, 15); dr = rotl(dr, 10);
  ar = fn3(ar, br, cr, dr, er, m[3], 0x6d703ef3, 11); cr = rotl(cr, 10);
  er = fn3(er, ar, br, cr, dr, m[7], 0x6d703ef3, 8); br = rotl(br, 10);
  dr = fn3(dr, er, ar, br, cr, m[14], 0x6d703ef3, 6); ar = rotl(ar, 10);
  cr = fn3(cr, dr, er, ar, br, m[6], 0x6d703ef3, 6); er = rotl(er, 10);
  br = fn3(br, cr, dr, er, ar, m[9], 0x6d703ef3, 14); dr = rotl(dr, 10);
  ar = fn3(ar, br, cr, dr, er, m[11], 0x6d703ef3, 12); cr = rotl(cr, 10);
  er = fn3(er, ar, br, cr, dr, m[8], 0x6d703ef3, 13); br = rotl(br, 10);
  dr = fn3(dr, er, ar, br, cr, m[12], 0x6d703ef3, 5); ar = rotl(ar, 10);
  cr = fn3(cr, dr, er, ar, br, m[2], 0x6d703ef3, 14); er = rotl(er, 10);
  br = fn3(br, cr, dr, er, ar, m[10], 0x6d703ef3, 13); dr = rotl(dr, 10);
  ar = fn3(ar, br, cr, dr, er, m[0], 0x6d703ef3, 13); cr = rotl(cr, 10);
  er = fn3(er, ar, br, cr, dr, m[4], 0x6d703ef3, 7); br = rotl(br, 10);
  dr = fn3(dr, er, ar, br, cr, m[13], 0x6d703ef3, 5); ar = rotl(ar, 10);

  // M'j = 8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14
  // K' = 0x7a6d76e9
  // S'j = 15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8
  cr = fn2(cr, dr, er, ar, br, m[8], 0x7a6d76e9, 15); er = rotl(er, 10);
  br = fn2(br, cr, dr, er, ar, m[6], 0x7a6d76e9, 5); dr = rotl(dr, 10);
  ar = fn2(ar, br, cr, dr, er, m[4], 0x7a6d76e9, 8); cr = rotl(cr, 10);
  er = fn2(er, ar, br, cr, dr, m[1], 0x7a6d76e9, 11); br = rotl(br, 10);
  dr = fn2(dr, er, ar, br, cr, m[3], 0x7a6d76e9, 14); ar = rotl(ar, 10);
  cr = fn2(cr, dr, er, ar, br, m[11], 0x7a6d76e9, 14); er = rotl(er, 10);
  br = fn2(br, cr, dr, er, ar, m[15], 0x7a6d76e9, 6); dr = rotl(dr, 10);
  ar = fn2(ar, br, cr, dr, er, m[0], 0x7a6d76e9, 14); cr = rotl(cr, 10);
  er = fn2(er, ar, br, cr, dr, m[5], 0x7a6d76e9, 6); br = rotl(br, 10);
  dr = fn2(dr, er, ar, br, cr, m[12], 0x7a6d76e9, 9); ar = rotl(ar, 10);
  cr = fn2(cr, dr, er, ar, br, m[2], 0x7a6d76e9, 12); er = rotl(er, 10);
  br = fn2(br, cr, dr, er, ar, m[13], 0x7a6d76e9, 9); dr = rotl(dr, 10);
  ar = fn2(ar, br, cr, dr, er, m[9], 0x7a6d76e9, 12); cr = rotl(cr, 10);
  er = fn2(er, ar, br, cr, dr, m[7], 0x7a6d76e9, 5); br = rotl(br, 10);
  dr = fn2(dr, er, ar, br, cr, m[10], 0x7a6d76e9, 15); ar = rotl(ar, 10);
  cr = fn2(cr, dr, er, ar, br, m[14], 0x7a6d76e9, 8); er = rotl(er, 10);

  // M'j = 12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11
  // K' = 0x00000000
  // S'j = 8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11
  br = fn1(br, cr, dr, er, ar, m[12], 0x00000000, 8); dr = rotl(dr, 10);
  ar = fn1(ar, br, cr, dr, er, m[15], 0x00000000, 5); cr = rotl(cr, 10);
  er = fn1(er, ar, br, cr, dr, m[10], 0x00000000, 12); br = rotl(br, 10);
  dr = fn1(dr, er, ar, br, cr, m[4], 0x00000000, 9); ar = rotl(ar, 10);
  cr = fn1(cr, dr, er, ar, br, m[1], 0x00000000, 12); er = rotl(er, 10);
  br = fn1(br, cr, dr, er, ar, m[5], 0x00000000, 5); dr = rotl(dr, 10);
  ar = fn1(ar, br, cr, dr, er, m[8], 0x00000000, 14); cr = rotl(cr, 10);
  er = fn1(er, ar, br, cr, dr, m[7], 0x00000000, 6); br = rotl(br, 10);
  dr = fn1(dr, er, ar, br, cr, m[6], 0x00000000, 8); ar = rotl(ar, 10);
  cr = fn1(cr, dr, er, ar, br, m[2], 0x00000000, 13); er = rotl(er, 10);
  br = fn1(br, cr, dr, er, ar, m[13], 0x00000000, 6); dr = rotl(dr, 10);
  ar = fn1(ar, br, cr, dr, er, m[14], 0x00000000, 5); cr = rotl(cr, 10);
  er = fn1(er, ar, br, cr, dr, m[0], 0x00000000, 15); br = rotl(br, 10);
  dr = fn1(dr, er, ar, br, cr, m[3], 0x00000000, 13); ar = rotl(ar, 10);
  cr = fn1(cr, dr, er, ar, br, m[9], 0x00000000, 11); er = rotl(er, 10);
  br = fn1(br, cr, dr, er, ar, m[11], 0x00000000, 11); dr = rotl(dr, 10);

  // change state
  var t = (this._h[1] + cl + dr) | 0;
  this._h[1] = (this._h[2] + dl + er) | 0;
  this._h[2] = (this._h[3] + el + ar) | 0;
  this._h[3] = (this._h[4] + al + br) | 0;
  this._h[4] = (this._h[0] + bl + cr) | 0;
  this._h[0] = t;
};
