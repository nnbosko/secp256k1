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
 * @fileoverview UTF-8 string handling.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 * @author Matthew Wampler-Doty
 */

goog.provide('secp256k1.sjcl.codec.utf8String');
goog.require('secp256k1.sjcl.bitArray');

/**
 * Convert an array of signed 32 bit words to a UTF-8 encoded string.
 * @param {Array<number>} arr Signed 32 bit array of numbers to convert.
 * @return {string} The utf8Stringadecimal string representing the bytes in the array.
 */
secp256k1.sjcl.codec.utf8String.fromBits = function(arr) {
    var bl = secp256k1.sjcl.bitArray.bitLength(arr),
        out = new Array(bl / 8),
        i, tmp;
    for (i = 0; i < bl / 8; i++) {
        if ((i & 3) === 0) {
            tmp = arr[i / 4];
        }
        out[i] = String.fromCharCode(tmp >>> 24);
        tmp <<= 8;
    }
    return decodeURIComponent(escape(out.join('')));
};

/** 
 * Convert a UTF-8 encoded string to an array of signed 32 bit words.
 * @param {string} str A UTF-8 encoded string.
 * @return {Array<number>} An array of signed 32 bit words representing the input.
 */
secp256k1.sjcl.codec.utf8String.toBits = function(str) {
    str = unescape(encodeURIComponent(str));
    var out = new Array(Math.ceil(str.length / 4)), 
	i, j = 0, tmp = 0;
    for (i = 0; i < str.length; i++) {
        tmp = tmp << 8 | str.charCodeAt(i);
        if ((i & 3) === 3) {
            out[j++] = tmp;
            tmp = 0;
        }
    }
    if (i & 3) {
        out[j] = secp256k1.sjcl.bitArray.partial(8 * (i & 3), tmp);
    }
    return out;
};
