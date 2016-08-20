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
 * @fileoverview Elliptic Curve Fields for SJCL.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 * @author Matthew Wampler-Doty
 */

goog.provide('secp256k1.sjcl.ecc.ECPoint');
goog.require('secp256k1.sjcl.bn');
goog.require('secp256k1.sjcl.bitArray');
goog.require('secp256k1.sjcl.bn.prime');
goog.require('secp256k1.sjcl.bn.prime.Field');

/**
 * Represents a point on a curve in affine coordinates.
 * @constructor
 * @param {!secp256k1.sjcl.ecc.ECPoint.curve} curve The curve that this point lies on.
 * @param {string|number|secp256k1.sjcl.bn} x The x coordinate.
 * @param {string|number|secp256k1.sjcl.bn} y The y coordinate.
 * @struct
 */
secp256k1.sjcl.ecc.ECPoint = function (curve, x, y) {
    /**
     * X coordinate for curve point
     * @const
     * @type {secp256k1.sjcl.bn}
     */
    this.x = x ? (x instanceof secp256k1.sjcl.bn ? x : new secp256k1.sjcl.bn(x)) : null;

    /**
     * Y coordinate for curve point
     * @const
     * @type {secp256k1.sjcl.bn}
     */
    this.y = x ? (y instanceof secp256k1.sjcl.bn ? y : new secp256k1.sjcl.bn(y)) : null;

    /**
     * Whether this is the point at infinity (it is so this is true
     * @const
     * @type {boolean}
     */
    this.isIdentity = x ? false : true;

    /**
     * @type {!secp256k1.sjcl.ecc.ECPoint.curve}
     * @const
     */
    this.curve = curve;

    /**
     * Array of multiples of this point.  Lazily initialized.
     * @type {Array<secp256k1.sjcl.ecc.ECPoint>}
     * @private
     */
    this._multiples = null;
};

/**
 * Construct the identity element
 * @param {!secp256k1.sjcl.ecc.ECPoint.curve} curve
 * @returns {!secp256k1.sjcl.ecc.ECPoint}
 */
secp256k1.sjcl.ecc.ECPoint.identity = function (curve) {
    return new secp256k1.sjcl.ecc.ECPoint(curve, null, null);
};


secp256k1.sjcl.ecc.ECPoint.prototype = {
    mult: function (k) {
        return this.toJac().mult(k, this).toAffine();
    },

    /**
     * Multiply this point by k, added to affine2*k2, and return the answer in Jacobian coordinates.
     * @param {secp256k1.sjcl.bn} k The coefficient to multiply this by.
     * @param {secp256k1.sjcl.bn} k2 The coefficient to multiply affine2 this by.
     * @param {secp256k1.sjcl.ecc.ECPoint} affine2 The other point in affine coordinates.
     * @return {secp256k1.sjcl.ecc.ECPoint} The result of the multiplication and addition.
     */
    mult2: function (k, k2, affine2) {
        return this.toJac().mult2(k, this, k2, affine2).toAffine();
    },

    isValid: function () {
        return this.y.square().equals(this.curve.b.add(this.x.mul(this.curve.a.add(this.x.square()))));
    }
};

/**
 * Lazily initialize an array of the first 16 multiples of this ECPoint and return them.
 * @returns {Array<secp256k1.sjcl.ecc.ECPoint>} The multiples of this point from 0 to 15
 */
secp256k1.sjcl.ecc.ECPoint.prototype.multiples = function () {
    var i, j;
    if (this._multiples === null) {
        this._multiples = new Array(16);
        j = this.toJac().doubl();
        this._multiples[0] = secp256k1.sjcl.ecc.ECPoint.identity(this.curve);
        this._multiples[1] = new secp256k1.sjcl.ecc.ECPoint(this.curve, this.x, this.y);
        this._multiples[2] = j.toAffine();
        for (i = 3; i < 16; i++) {
            j = j.add(this);
            this._multiples[i] = j.toAffine();
        }
    }
    return this._multiples;
};

secp256k1.sjcl.ecc.ECPoint.prototype.toJac = function () {
    return new secp256k1.sjcl.ecc.ECPoint.Jac(this.curve, this.x, this.y, secp256k1.sjcl.bn.ONE);
};

/**
 * Negate this ECPoint
 * @returns {!secp256k1.sjcl.ecc.ECPoint}
 */
secp256k1.sjcl.ecc.ECPoint.prototype.negate = function () {
    //noinspection JSCheckFunctionSignatures
    return new secp256k1.sjcl.ecc.ECPoint(this.curve, this.x, this.curve.field.modulus.sub(this.y));
};

/**
 * Represents a point on a curve in Jacobian coordinates. Coordinates can be specified as secp256k1.sjcl.bns or strings (which
 * will be converted to secp256k1.sjcl.bns).
 *
 * @constructor
 * @param {secp256k1.sjcl.ecc.ECPoint.curve} curve The curve that this point lies on.
 * @param {secp256k1.sjcl.bn} x The x coordinate.
 * @param {secp256k1.sjcl.bn} y The y coordinate.
 * @param {secp256k1.sjcl.bn} z The z coordinate.
 */
secp256k1.sjcl.ecc.ECPoint.Jac = function (curve, x, y, z) {
    if (x === undefined || x === null) {
        this.isIdentity = true;
    } else {
        this.x = x;
        this.y = y;
        this.z = z;
        this.isIdentity = false;
    }
    this.curve = curve;
};

secp256k1.sjcl.ecc.ECPoint.Jac.prototype = {

    /**
     * Multiply this point by k and return the answer in Jacobian coordinates.
     * @param {number|secp256k1.sjcl.bn} k The coefficient to multiply by.
     * @param {secp256k1.sjcl.ecc.ECPoint} affine This point in affine coordinates.
     * @return {secp256k1.sjcl.ecc.ECPoint.Jac} The result of the multiplication, in Jacobian coordinates.
     */
    mult: function (k, affine) {
        if (typeof(k) === "number") {
            k = [k];
        } else if (k.limbs !== undefined) {
            k = k.normalize().limbs;
        }

        var i, j,
            out = new secp256k1.sjcl.ecc.ECPoint(this.curve, null, null).toJac(),
            multiples = affine.multiples();

        for (i = k.length - 1; i >= 0; i--) {
            for (j = secp256k1.sjcl.bn.radix - 4; j >= 0; j -= 4) {
                out = out.doubl().doubl().doubl().doubl().add(multiples[k[i] >> j & 0xF]);
            }
        }

        return out;
    },

    /**
     * Multiply this point by k, added to affine2*k2, and return the answer in Jacobian coordinates.
     * @param {secp256k1.sjcl.bn|number} k1 The coefficient to multiply this by.
     * @param {secp256k1.sjcl.ecc.ECPoint} affine This point in affine coordinates.
     * @param {secp256k1.sjcl.bn|number} k2 The coefficient to multiply affine2 this by.
     * @param {secp256k1.sjcl.ecc.ECPoint} affine2 The other point in affine coordinates.
     * @return {secp256k1.sjcl.ecc.ECPoint.Jac} The result of the multiplication and addition, in Jacobian coordinates.
     */
    mult2: function (k1, affine, k2, affine2) {
        if (typeof(k1) === "number") {
            k1 = [k1];
        } else if (k1.limbs !== undefined) {
            k1 = k1.normalize().limbs;
        }

        if (typeof(k2) === "number") {
            k2 = [k2];
        } else if (k2.limbs !== undefined) {
            k2 = k2.normalize().limbs;
        }

        var i, j, out = new secp256k1.sjcl.ecc.ECPoint(this.curve, null, null).toJac(), m1 = affine.multiples(),
            m2 = affine2.multiples(), l1, l2;

        for (i = Math.max(k1.length, k2.length) - 1; i >= 0; i--) {
            l1 = k1[i] | 0;
            l2 = k2[i] | 0;
            for (j = secp256k1.sjcl.bn.radix - 4; j >= 0; j -= 4) {
                out = out.doubl().doubl().doubl().doubl().add(m1[l1 >> j & 0xF]).add(m2[l2 >> j & 0xF]);
            }
        }

        return out;
    },

    isValid: function () {
        var z2 = this.z.square(), z4 = z2.square(), z6 = z4.mul(z2);
        return this.y.square().equals(
            this.curve.b.mul(z6).add(this.x.mul(
                this.curve.a.mul(z4).add(this.x.square()))));
    }
};

/**
 * Negate this point and return the results in Jacobian coordinates.
 * @return {!secp256k1.sjcl.ecc.ECPoint.Jac}
 */
secp256k1.sjcl.ecc.ECPoint.Jac.prototype.negate = function () {
    return this.toAffine().negate().toJac();
};

/**
 * Adds `this` and an ECPoint `p` and returns the result in Jacobian coordinates.
 * Note that `p` must be in affine coordinates.
 * @param {!secp256k1.sjcl.ecc.ECPoint} p The other point to add, in affine coordinates.
 * @return {!secp256k1.sjcl.ecc.ECPoint.Jac} The sum of the two points, in Jacobian coordinates.
 */
secp256k1.sjcl.ecc.ECPoint.Jac.prototype.add = function (p) {
    var reduce = secp256k1.sjcl.bn.prime.reduce,
        field = this.curve.field,
        sz2, c, d, c2, x1, x2, x, y1, y2, y, z;
    if (this.curve !== p.curve) {
        throw new Error("secp256k1.sjcl.ecc.add(): Points must be on the same curve to add them!");
    }

    if (this.isIdentity) {
        return p.toJac();
    } else if (p.isIdentity) {
        return this;
    }

    sz2 = reduce(this.z.square(), field);
    c = reduce(p.x.mul(sz2).subM(this.x), field);

    // TODO: Also check c.equals(0)?
    if (c.equals(field.modulus, false)) {
        if (this.y.equals(p.y.mul(sz2.mul(this.z)))) {
            return this.doubl();
        } else {
            // inverses
            return new secp256k1.sjcl.ecc.ECPoint.Jac(this.curve, null, null, null);
        }
    }

    d = reduce(p.y.mul(sz2.mul(this.z)).subM(this.y), field);
    c2 = reduce(c.square(), field);

    x1 = reduce(d.square(), field);
    x2 = reduce(c.square().mul(c).addM(this.x.add(this.x).mul(c2)), field);
    x = reduce(x1.subM(x2), field);

    y1 = reduce(this.x.mul(c2).subM(x).mul(d), field);
    y2 = reduce(this.y.mul(c.square().mul(c)), field);
    y = reduce(y1.subM(y2), field);

    z = reduce(this.z.mul(c), field);

    return new secp256k1.sjcl.ecc.ECPoint.Jac(this.curve, x, y, z);
};

/**
 * Returns a copy of this point converted to affine coordinates.
 * @return {secp256k1.sjcl.ecc.ECPoint} The converted point.
 */
secp256k1.sjcl.ecc.ECPoint.Jac.prototype.toAffine = function () {
    if (this.isIdentity || this.z.equals(0)) {
        return new secp256k1.sjcl.ecc.ECPoint(this.curve, null, null);
    }
    var modulus = this.curve.field.modulus,
        fullReduce = secp256k1.sjcl.bn.prime.fullReduce,
        reduce = secp256k1.sjcl.bn.prime.reduce,
        field = this.curve.field,
        zi = this.z.inverseMod(modulus),
        zi2 = reduce(zi.square(), field);
    return new secp256k1.sjcl.ecc.ECPoint(
        this.curve,
        fullReduce(this.x.mul(zi2), field),
        fullReduce(this.y.mul(zi2.mul(zi)), field));
};

/**
 * Doubles this point.
 * @return {!secp256k1.sjcl.ecc.ECPoint.Jac} The doubled point.
 */
secp256k1.sjcl.ecc.ECPoint.Jac.prototype.doubl = function () {
    if (this.isIdentity) {
        return this;
    }
    var reduce = secp256k1.sjcl.bn.prime.reduce,
        field = this.curve.field,
        y2 = reduce(this.y.square(), field),
        z4 = reduce(this.z.square().square(), field),
        s = reduce(y2.mul(this.x), field).mul(4),
        m = reduce(this.x.square().mul(3).addM(this.curve.a.mul(z4)), field),
        x = reduce(m.square().subM(s.add(s)), field),
        y = reduce(m.mul(s.subM(x)).subM(y2.square().mul(8)), field),
        z = reduce(this.y.add(this.y).mul(this.z), field);
    return new secp256k1.sjcl.ecc.ECPoint.Jac(this.curve, x, y, z);
};

/**
 * Construct an elliptic curve. Most users will not use this and instead start with one of the NIST curves defined below.
 *
 * @constructor
 * @struct
 * @this {secp256k1.sjcl.ecc.ECPoint.curve}
 * @param {secp256k1.sjcl.bn.prime.Field} field The prime modulus field.
 * @param {secp256k1.sjcl.bn|string|number} r The prime order of the curve.
 * @param {secp256k1.sjcl.bn|string|number} a The constant a in the equation of the curve y^2 = x^3 + ax + b (for NIST curves, a is always -3).
 * @param {secp256k1.sjcl.bn|string|number} b The constant b in the equation of the curve y^2 = x^3 + ax + b.
 * @param {secp256k1.sjcl.bn|string|number} x The x coordinate of a base point of the curve.
 * @param {secp256k1.sjcl.bn|string|number} y The y coordinate of a base point of the curve.
 */
secp256k1.sjcl.ecc.ECPoint.curve = function (field, r, a, b, x, y) {
    this.field = field;

    /**
     * The prime order of the curve.
     * @final
     * @type {secp256k1.sjcl.bn}
     */

    this.r = (r instanceof secp256k1.sjcl.bn) ? r : new secp256k1.sjcl.bn(r);

    /**
     * The first coefficient of the curve equation.
     * @final
     * @type {secp256k1.sjcl.bn}
     */
    this.a = (a instanceof secp256k1.sjcl.bn) ? a : new secp256k1.sjcl.bn(a);

    /**
     * The second coefficient fo the curve equation.
     * @final
     * @type {secp256k1.sjcl.bn}
     */
    this.b = (b instanceof secp256k1.sjcl.bn) ? b : new secp256k1.sjcl.bn(b);

    //noinspection JSUnusedGlobalSymbols
    /**
     * Generator point.
     * @final
     * @type {secp256k1.sjcl.ecc.ECPoint}
     */
    this.G = new secp256k1.sjcl.ecc.ECPoint(this, x, y);
};