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

/** @fileoverview Arrays of bits, encoded as arrays of Numbers.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 * @author Matthew Wampler-Doty
 */

goog.provide('secp256k1.sjcl.bitArray');

/**
 * Arrays of bits, encoded as arrays of Numbers (signed 32 bit words).
 *
 * @description
 * 
 * These objects are the currency accepted by SJCL's crypto functions.
 * 
 * Most of our crypto primitives operate on arrays of 4-byte words internally,
 * but many of them can take arguments that are not a multiple of 4 bytes.
 * This library encodes arrays of bits (whose size need not be a multiple of 8
 * bits) as arrays of 32-bit words.  The bits are packed, big-endian, into an
 * array of words, 32 bits at a time.  Since the words are double-precision
 * floating point numbers, they fit some extra data.  We use this (in a private,
 * possibly-changing manner) to encode the number of bits actually  present
 * in the last word of the array.
 *
 * Because bitwise ops clear this out-of-band data, these arrays can be passed
 * to ciphers like AES which want arrays of words.
 */

/**
 * Array slices in units of bits.
 * @param {Array<number>} a The array to slice.
 * @param {Number} bstart The offset to the start of the slice, in bits.
 * @param {Number} bend The offset to the end of the slice, in bits.  If this is undefined,
 * slice until the end of the array.
 * @return {Array<number>} The requested slice.
 */
secp256k1.sjcl.bitArray.bitSlice = function(a, bstart, bend) {
    a = secp256k1.sjcl.bitArray._shiftRight(a.slice(bstart / 32), 32 - (bstart & 31)).slice(1);
    return (bend === undefined) ? a : secp256k1.sjcl.bitArray.clamp(a, bend - bstart);
};

/**
 * Extract a number packed into a bit array.
 * @param {Array<number>} a The array to slice.
 * @param {Number} bstart The offset to the start of the slice, in bits.
 * @param {Number} blength The length of the number to extract.
 * @return {Number} The requested slice.
 */
secp256k1.sjcl.bitArray.extract = function(a, bstart, blength) {
    var x, sh = Math.floor((-bstart - blength) & 31);
    //noinspection JSBitwiseOperatorUsage
    if ((bstart + blength - 1 ^ bstart) & -32) {
        // it crosses a boundary
        x = (a[bstart / 32 | 0] << (32 - sh)) ^ (a[bstart / 32 + 1 | 0] >>> sh);
    } else {
        // within a single word
        x = a[bstart / 32 | 0] >>> sh;
    }
    return x & ((1 << blength) - 1);
};

/**
 * Concatenate two bit arrays.
 * @param {Array<number>} a1 The first array.
 * @param {Array<number>} a2 The second array.
 * @return {Array<number>} The concatenation of a1 and a2.
 */
secp256k1.sjcl.bitArray.concat = function(a1, a2) {
    if (a1.length === 0 || a2.length === 0) {
        return a1.concat(a2);
    }

    var last = a1[a1.length - 1],
        shift = secp256k1.sjcl.bitArray.getPartial(last);
    if (shift === 32) {
        return a1.concat(a2);
    } else {
        return secp256k1.sjcl.bitArray._shiftRight(a2, shift, last | 0, a1.slice(0, a1.length - 1));
    }
};

/**
 * Find the length of an array of bits.
 * @param {Array<number>} a The array.
 * @return {Number} The length of a, in bits.
 */
secp256k1.sjcl.bitArray.bitLength = function(a) {
    var l = a.length,
        x;
    if (l === 0) {
        return 0;
    }
    x = a[l - 1];
    return (l - 1) * 32 + secp256k1.sjcl.bitArray.getPartial(x);
};

/**
 * Truncate an array.
 * @param {Array<number>} a The array.
 * @param {Number} len The length to truncate to, in bits.
 * @return {Array<number>} A new array, truncated to len bits.
 */
secp256k1.sjcl.bitArray.clamp = function(a, len) {
    if (a.length * 32 < len) {
        return a;
    }
    a = a.slice(0, Math.ceil(len / 32));
    var l = a.length;
    len = len & 31;
    if (l > 0 && len) {
        a[l - 1] = secp256k1.sjcl.bitArray.partial(len, a[l - 1] & 0x80000000 >> (len - 1), 1);
    }
    return a;
};

/**
 * Make a partial word for a bit array.
 * @param {Number} len The number of bits in the word.
 * @param {Number} x The bits.
 * @param {Number} [_end=0] Pass 1 if x has already been shifted to the high side.
 * @return {Number} The partial word.
 */
secp256k1.sjcl.bitArray.partial = function(len, x, _end) {
    if (len === 32) {
        return x;
    }
    return (_end ? x | 0 : x << (32 - len)) + len * 0x10000000000;
};

/**
 * Get the number of bits used by a partial word.
 * @param {Number} x The partial word.
 * @return {Number} The number of bits used by the partial word.
 */
secp256k1.sjcl.bitArray.getPartial = function(x) {
    return Math.round(x / 0x10000000000) || 32;
};

/**
 * Compare two arrays for equality in a predictable amount of time.
 * @param {Array<number>} a The first array.
 * @param {Array<number>} b The second array.
 * @return {boolean} true if a == b; false otherwise.
 */
secp256k1.sjcl.bitArray.equal = function(a, b) {
    if (secp256k1.sjcl.bitArray.bitLength(a) !== secp256k1.sjcl.bitArray.bitLength(b)) {
        return false;
    }
    var x = 0,
        i;
    for (i = 0; i < a.length; i++) {
        x |= a[i] ^ b[i];
    }
    return (x === 0);
};

/** 
 * Shift an array right.
 * @param {Array<number>} a The array to shift.
 * @param {Number} shift The number of bits to shift.
 * @param {Number} [carry=0] A byte to carry in
 * @param {Array<number>} [out=[]] An array to prepend to the output.
 * @private
 */
secp256k1.sjcl.bitArray._shiftRight = function(a, shift, carry, out) {
    var i, last2, shift2;
    if (out === undefined) {
        out = [];
    }

    for (; shift >= 32; shift -= 32) {
        out.push(carry);
        carry = 0;
    }

    if (shift === 0) {
        return out.concat(a);
    }

    for (i = 0; i < a.length; i++) {
        out.push(carry | a[i] >>> shift);
        carry = a[i] << (32 - shift);
    }

    last2 = a.length ? a[a.length - 1] : 0;
    shift2 = secp256k1.sjcl.bitArray.getPartial(last2);
    out.push(secp256k1.sjcl.bitArray.partial(shift + shift2 & 31, (shift + shift2 > 32) ? carry : out.pop(), 1));
    return out;
};

/** 
 * Byteswap a word array inplace.
 * (does not handle partial words)
 * @param {Array<number>} a word array.
 * @return {Array<number>} Byteswapped array.
 */
secp256k1.sjcl.bitArray.byteswapM = function(a) {
    var i, v, m = 0xff00;
    for (i = 0; i < a.length; ++i) {
        v = a[i];
        a[i] = (v >>> 24) | ((v >>> 8) & m) | ((v & m) << 8) | (v << 24);
    }
    return a;
};
