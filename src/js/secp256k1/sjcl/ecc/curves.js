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
 * @fileoverview (PseudoMersenne) Elliptic curve fields.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 * @author Matthew Wampler-Doty
 */

goog.provide('secp256k1.sjcl.ecc.curves');
goog.require('secp256k1.sjcl.ecc.ECPoint');
goog.require('secp256k1.sjcl.bn.prime');

/**
 * @const
 * @type {!secp256k1.sjcl.ecc.ECPoint.curve}
 */
secp256k1.sjcl.ecc.curves.c192 =
    new secp256k1.sjcl.ecc.ECPoint.curve(
        secp256k1.sjcl.bn.prime.p192,
        "0xffffffffffffffffffffffff99def836146bc9b1b4d22831",
        -3,
        "0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1",
        "0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012",
        "0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811");

/**
 * @const
 * @type {!secp256k1.sjcl.ecc.ECPoint.curve}
 */
secp256k1.sjcl.ecc.curves.c224 =
    new secp256k1.sjcl.ecc.ECPoint.curve(
        secp256k1.sjcl.bn.prime.p224,
        "0xffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d",
        -3,
        "0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4",
        "0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21",
        "0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34");

/**
 * @const
 * @type {!secp256k1.sjcl.ecc.ECPoint.curve}
 */
secp256k1.sjcl.ecc.curves.c256 =
    new secp256k1.sjcl.ecc.ECPoint.curve(
        secp256k1.sjcl.bn.prime.p256,
        "0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        -3,
        "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
        "0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");

/**
 * @const
 * @type {!secp256k1.sjcl.ecc.ECPoint.curve}
 */
secp256k1.sjcl.ecc.curves.c384 =
    new secp256k1.sjcl.ecc.ECPoint.curve(
        secp256k1.sjcl.bn.prime.p384,
        "0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
        -3,
        "0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
        "0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
        "0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f");

/**
 * @const
 * @type {!secp256k1.sjcl.ecc.ECPoint.curve}
 */
secp256k1.sjcl.ecc.curves.c521 =
    new secp256k1.sjcl.ecc.ECPoint.curve(
        secp256k1.sjcl.bn.prime.p521,
        "0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409",
        -3,
        "0x051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00",
        "0xC6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66",
        "0x11839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650");

/**
 * @const
 * @type {!secp256k1.sjcl.ecc.ECPoint.curve}
 */
secp256k1.sjcl.ecc.curves.k192 =
    new secp256k1.sjcl.ecc.ECPoint.curve(
        secp256k1.sjcl.bn.prime.p192k,
        "0xfffffffffffffffffffffffe26f2fc170f69466a74defd8d",
        0,
        3,
        "0xdb4ff10ec057e9ae26b07d0280b7f4341da5d1b1eae06c7d",
        "0x9b2f2f6d9c5628a7844163d015be86344082aa88d95e2f9d");

/**
 * @const
 * @type {!secp256k1.sjcl.ecc.ECPoint.curve}
 */
secp256k1.sjcl.ecc.curves.k224 =
    new secp256k1.sjcl.ecc.ECPoint.curve(
        secp256k1.sjcl.bn.prime.p224k,
        "0x010000000000000000000000000001dce8d2ec6184caf0a971769fb1f7",
        0,
        5,
        "0xa1455b334df099df30fc28a169a467e9e47075a90f7e650eb6b7a45c",
        "0x7e089fed7fba344282cafbd6f7e319f7c0b0bd59e2ca4bdb556d61a5");

/**
 * @const
 * @type {!secp256k1.sjcl.ecc.ECPoint.curve}
 */
secp256k1.sjcl.ecc.curves.k256 =
    new secp256k1.sjcl.ecc.ECPoint.curve(
        secp256k1.sjcl.bn.prime.p256k,
        "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
        0,
        7,
        "0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        "0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8");