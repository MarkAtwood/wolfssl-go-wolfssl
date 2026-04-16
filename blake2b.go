/* blake2b.go
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
// #include <wolfssl/wolfcrypt/hash.h>
// #include <wolfssl/wolfcrypt/blake2.h>
// #ifndef HAVE_BLAKE2B
// typedef struct Blake2b {} Blake2b;
// static int wc_InitBlake2b(Blake2b* b, word32 digestSz) {
//     (void)b; (void)digestSz; return -174;
// }
// static int wc_InitBlake2b_WithKey(Blake2b* b, word32 digestSz,
//                                   const byte* key, word32 keylen) {
//     (void)b; (void)digestSz; (void)key; (void)keylen; return -174;
// }
// static int wc_Blake2bUpdate(Blake2b* b2b, const byte* data, word32 sz) {
//     (void)b2b; (void)data; (void)sz; return -174;
// }
// static int wc_Blake2bFinal(Blake2b* b2b, byte* final, word32 requestSz) {
//     (void)b2b; (void)final; (void)requestSz; return -174;
// }
// #endif
import "C"
import "unsafe"

const WC_BLAKE2B_512_DIGEST_SIZE = 64
const WC_BLAKE2B_256_DIGEST_SIZE = 32

type Blake2b = C.struct_Blake2b

// Wc_InitBlake2b initializes a BLAKE2b context with the given digest size in
// bytes (up to WC_BLAKE2B_512_DIGEST_SIZE).
// Returns 0 on success, negative on error.
func Wc_InitBlake2b(b *C.struct_Blake2b, digestSz int) int {
    return int(C.wc_InitBlake2b(b, C.word32(digestSz)))
}

// Wc_InitBlake2b_WithKey initializes a BLAKE2b context with a MAC key.
// Returns 0 on success, negative on error.
func Wc_InitBlake2b_WithKey(b *C.struct_Blake2b, digestSz int, key []byte) int {
    var sanKey *C.byte
    if len(key) > 0 {
        sanKey = (*C.byte)(unsafe.Pointer(&key[0]))
    }
    return int(C.wc_InitBlake2b_WithKey(b, C.word32(digestSz),
        sanKey, C.word32(len(key))))
}

// Wc_Blake2bUpdate feeds data into a BLAKE2b context.
// sz must be <= len(in).
// Returns 0 on success, negative on error.
func Wc_Blake2bUpdate(b *C.struct_Blake2b, in []byte, sz int) int {
    if sz < 0 || sz > len(in) {
        return BAD_FUNC_ARG
    }
    var sanIn *C.byte
    if len(in) > 0 {
        sanIn = (*C.byte)(unsafe.Pointer(&in[0]))
    } else {
        sanIn = (*C.byte)(unsafe.Pointer(nil))
    }
    return int(C.wc_Blake2bUpdate(b, sanIn, C.word32(sz)))
}

// Wc_Blake2bFinal finalizes the BLAKE2b digest.
// out must have capacity >= requestSz.
// Returns 0 on success, negative on error.
func Wc_Blake2bFinal(b *C.struct_Blake2b, out []byte, requestSz int) int {
    if requestSz < 0 || requestSz > len(out) {
        return BAD_FUNC_ARG
    }
    if len(out) == 0 {
        return BAD_FUNC_ARG
    }
    return int(C.wc_Blake2bFinal(b, (*C.byte)(unsafe.Pointer(&out[0])),
        C.word32(requestSz)))
}
