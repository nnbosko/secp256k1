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
 * @fileoverview Utility for converting hexadecimal strings to arrays of signed 32 bit words and back.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 * @author Matthew Wampler-Doty
 */

goog.provide('secp256k1.sjcl.codec.hex');
goog.require('secp256k1.sjcl.bitArray');

/**
 * Convert an array of signed 32 bit numbers to a hexadecimal string.
 * @param {Array<number>} arr Signed 32 bit array of numbers to convert.
 * @return {string} The hexadecimal string representing the bytes in the array.
 */
secp256k1.sjcl.codec.hex.fromBits = function (arr) {
    var out = new Array(arr.length), i;
    for (i = 0; i < arr.length; i++) {
        out[i] = ((arr[i] | 0) + 0xF00000000000).toString(16).substr(4);
    }
    return out.join('').substr(0, secp256k1.sjcl.bitArray.bitLength(arr) / 4); //.replace(/(.{8})/g, "$1 ");
};

/**
 * Convert from a hex string to an array of signed 32 bit numbers.
 * @param {string} str A hexadecimal string.
 * @return {Array<number>} An array of signed 32 bit words representing the input.
 */
secp256k1.sjcl.codec.hex.toBits = function (str) {
    var i, j, out, len;
    str = str.replace(/\s|0x/g, "");
    len = str.length;
    str += "00000000";
    out = new Array(Math.floor(str.length / 8));
    for (i = 0, j = 0; i < str.length; i += 8, j++) {
        out[j] = parseInt(str.substr(i, 8), 16) ^ 0;
    }
    return secp256k1.sjcl.bitArray.clamp(out, len * 4);
};
