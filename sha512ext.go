/* sha512ext.go
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

package wolfSSL

// #include <wolfssl/options.h>
// #include <wolfssl/wolfcrypt/sha512.h>
//
// // SHA-512/224: guarded by WOLFSSL_SHA512 && !WOLFSSL_NOSHA512_224
// #if defined(WOLFSSL_SHA512) && !defined(WOLFSSL_NOSHA512_224) && \
//     (!defined(HAVE_FIPS) || FIPS_VERSION_GE(5,3)) && !defined(HAVE_SELFTEST)
// static int wc_go_InitSha512_224(wc_Sha512* sha) {
//     return wc_InitSha512_224(sha);
// }
// static int wc_go_Sha512_224Update(wc_Sha512* sha, const byte* d, word32 l) {
//     return wc_Sha512_224Update(sha, d, l);
// }
// static int wc_go_Sha512_224Final(wc_Sha512* sha, byte* h) {
//     return wc_Sha512_224Final(sha, h);
// }
// static void wc_go_Sha512_224Free(wc_Sha512* sha) {
//     wc_Sha512_224Free(sha);
// }
// #else
// static int wc_go_InitSha512_224(wc_Sha512* sha) {
//     (void)sha; return -174;
// }
// static int wc_go_Sha512_224Update(wc_Sha512* sha, const byte* d, word32 l) {
//     (void)sha; (void)d; (void)l; return -174;
// }
// static int wc_go_Sha512_224Final(wc_Sha512* sha, byte* h) {
//     (void)sha; (void)h; return -174;
// }
// static void wc_go_Sha512_224Free(wc_Sha512* sha) { (void)sha; }
// #endif
//
// // SHA-512/256: guarded by WOLFSSL_SHA512 && !WOLFSSL_NOSHA512_256
// #if defined(WOLFSSL_SHA512) && !defined(WOLFSSL_NOSHA512_256) && \
//     (!defined(HAVE_FIPS) || FIPS_VERSION_GE(5,3)) && !defined(HAVE_SELFTEST)
// static int wc_go_InitSha512_256(wc_Sha512* sha) {
//     return wc_InitSha512_256(sha);
// }
// static int wc_go_Sha512_256Update(wc_Sha512* sha, const byte* d, word32 l) {
//     return wc_Sha512_256Update(sha, d, l);
// }
// static int wc_go_Sha512_256Final(wc_Sha512* sha, byte* h) {
//     return wc_Sha512_256Final(sha, h);
// }
// static void wc_go_Sha512_256Free(wc_Sha512* sha) {
//     wc_Sha512_256Free(sha);
// }
// #else
// static int wc_go_InitSha512_256(wc_Sha512* sha) {
//     (void)sha; return -174;
// }
// static int wc_go_Sha512_256Update(wc_Sha512* sha, const byte* d, word32 l) {
//     (void)sha; (void)d; (void)l; return -174;
// }
// static int wc_go_Sha512_256Final(wc_Sha512* sha, byte* h) {
//     (void)sha; (void)h; return -174;
// }
// static void wc_go_Sha512_256Free(wc_Sha512* sha) { (void)sha; }
// #endif
import "C"
import "unsafe"

// Digest sizes for the truncated SHA-512 variants.
const WC_SHA512_224_DIGEST_SIZE = 28
const WC_SHA512_256_DIGEST_SIZE = 32

// wc_Sha512_224 and wc_Sha512_256 are both typedefs for struct wc_Sha512 in
// the wolfSSL headers.
type Wc_Sha512_224 = C.struct_wc_Sha512
type Wc_Sha512_256 = C.struct_wc_Sha512

// SHA-512/224

// Wc_InitSha512_224 initializes a SHA-512/224 streaming context.
// Returns 0 on success, negative on error.
func Wc_InitSha512_224(sha *Wc_Sha512_224) int {
    return int(C.wc_go_InitSha512_224(sha))
}

// Wc_Sha512_224Free releases resources held by a SHA-512/224 context.
func Wc_Sha512_224Free(sha *Wc_Sha512_224) {
    C.wc_go_Sha512_224Free(sha)
}

// Wc_Sha512_224Update feeds data into a SHA-512/224 context.
// inSz must be <= len(in).
// Returns 0 on success, negative on error.
func Wc_Sha512_224Update(sha *Wc_Sha512_224, in []byte, inSz int) int {
    if inSz < 0 || inSz > len(in) {
        return BAD_FUNC_ARG
    }
    var sanIn *C.byte
    if len(in) > 0 {
        sanIn = (*C.byte)(unsafe.Pointer(&in[0]))
    } else {
        sanIn = (*C.byte)(unsafe.Pointer(nil))
    }
    return int(C.wc_go_Sha512_224Update(sha, sanIn, C.word32(inSz)))
}

// Wc_Sha512_224Final finalizes the SHA-512/224 digest into out.
// out must have capacity >= WC_SHA512_224_DIGEST_SIZE (28 bytes).
// Returns 0 on success, negative on error.
func Wc_Sha512_224Final(sha *Wc_Sha512_224, out []byte) int {
    if len(out) < WC_SHA512_224_DIGEST_SIZE {
        return -173
    }
    return int(C.wc_go_Sha512_224Final(sha, (*C.byte)(unsafe.Pointer(&out[0]))))
}

// SHA-512/256

// Wc_InitSha512_256 initializes a SHA-512/256 streaming context.
// Returns 0 on success, negative on error.
func Wc_InitSha512_256(sha *Wc_Sha512_256) int {
    return int(C.wc_go_InitSha512_256(sha))
}

// Wc_Sha512_256Free releases resources held by a SHA-512/256 context.
func Wc_Sha512_256Free(sha *Wc_Sha512_256) {
    C.wc_go_Sha512_256Free(sha)
}

// Wc_Sha512_256Update feeds data into a SHA-512/256 context.
// inSz must be <= len(in).
// Returns 0 on success, negative on error.
func Wc_Sha512_256Update(sha *Wc_Sha512_256, in []byte, inSz int) int {
    if inSz < 0 || inSz > len(in) {
        return BAD_FUNC_ARG
    }
    var sanIn *C.byte
    if len(in) > 0 {
        sanIn = (*C.byte)(unsafe.Pointer(&in[0]))
    } else {
        sanIn = (*C.byte)(unsafe.Pointer(nil))
    }
    return int(C.wc_go_Sha512_256Update(sha, sanIn, C.word32(inSz)))
}

// Wc_Sha512_256Final finalizes the SHA-512/256 digest into out.
// out must have capacity >= WC_SHA512_256_DIGEST_SIZE (32 bytes).
// Returns 0 on success, negative on error.
func Wc_Sha512_256Final(sha *Wc_Sha512_256, out []byte) int {
    if len(out) < WC_SHA512_256_DIGEST_SIZE {
        return -173
    }
    return int(C.wc_go_Sha512_256Final(sha, (*C.byte)(unsafe.Pointer(&out[0]))))
}
