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
 * @fileoverview (PseudoMersenne) Prime fields and field points.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 * @author Matthew Wampler-Doty
 */

goog.provide('secp256k1.sjcl.bn.prime.Field');
goog.require('secp256k1.sjcl.bn');

/**
 * @constructor
 * @struct
 * @final
 * @param {!number} exponent Exponent of the power of two of the Pseudo-Mersenne Prime.
 * @param {!Array<!Array<number>>} coeff Coefficients that parametrizes the prime field.
 */
secp256k1.sjcl.bn.prime.Field = function (exponent, coeff) {
    this.exponent = exponent;

    var i,
        tmp = exponent / secp256k1.sjcl.bn.radix,
        mo = Math.ceil(tmp);

    /**
     * Offset for performing approximate modulus reductions
     * @type {number}
     */
    this.modOffset = mo;
    this.exponent = exponent;
    this.offset = new Array(coeff.length);
    this.factor = new Array(coeff.length);
    this.minOffset = mo;
    this.fullOffset = new Array(coeff.length);
    this.fullFactor = new Array(coeff.length);
    this.modulus = new secp256k1.sjcl.bn(Math.pow(2, exponent));
    this.fullMask = 0 | -Math.pow(2, exponent % secp256k1.sjcl.bn.radix);

    for (i = 0; i < coeff.length; i++) {
        this.offset[i] = Math.floor(coeff[i][0] / secp256k1.sjcl.bn.radix - tmp);
        this.fullOffset[i] = Math.ceil(coeff[i][0] / secp256k1.sjcl.bn.radix - tmp);
        this.factor[i] = coeff[i][1] * Math.pow(1 / 2, exponent - coeff[i][0] + this.offset[i] * secp256k1.sjcl.bn.radix);
        this.fullFactor[i] = coeff[i][1] *
            Math.pow(1 / 2, exponent - coeff[i][0] + this.fullOffset[i] * secp256k1.sjcl.bn.radix);
        this.modulus.addM(new secp256k1.sjcl.bn(Math.pow(2, coeff[i][0]) * coeff[i][1]));
        this.minOffset = Math.min(this.minOffset, -this.offset[i]); // conservative
    }
};