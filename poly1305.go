/* poly1305.go
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

// #cgo CFLAGS: -I/usr/include -I/usr/include/wolfssl -I/usr/local/include -I/usr/local/include/wolfssl
// #cgo LDFLAGS: -L/usr/local/lib -lwolfssl
// #include <wolfssl/options.h>
// #include <wolfssl/wolfcrypt/poly1305.h>
// #ifndef HAVE_POLY1305
// #define POLY1305_DIGEST_SIZE 16
// static int wc_Poly1305SetKey(void* p, const unsigned char* key, unsigned int sz) { (void)p; (void)key; (void)sz; return -174; }
// static int wc_Poly1305Update(void* p, const unsigned char* m, unsigned int bytes) { (void)p; (void)m; (void)bytes; return -174; }
// static int wc_Poly1305Final(void* p, unsigned char* tag) { (void)p; (void)tag; return -174; }
// static int wc_Poly1305_MAC(void* p, const unsigned char* additional, unsigned int addSz, const unsigned char* input, unsigned int sz, unsigned char* tag, unsigned int tagSz) { (void)p; (void)additional; (void)addSz; (void)input; (void)sz; (void)tag; (void)tagSz; return -174; }
// #endif
import "C"
import (
    "unsafe"
)

type Poly1305 = C.struct_Poly1305

const POLY1305_DIGEST_SIZE = int(C.POLY1305_DIGEST_SIZE)

func Wc_Poly1305SetKey(poly1305 *C.struct_Poly1305, key []byte) int {
    if len(key) < 32 {
        return BAD_FUNC_ARG
    }
    return int(C.wc_Poly1305SetKey(poly1305, (*C.uchar)(unsafe.Pointer(&key[0])), C.word32(len(key))))
}

func Wc_Poly1305Update(poly1305 *C.struct_Poly1305, in []byte, inSz int) int {
    if inSz < 0 || inSz > len(in) {
        return BAD_FUNC_ARG
    }
    var sanIn *C.uchar
    if inSz > 0 {
        sanIn = (*C.uchar)(unsafe.Pointer(&in[0]))
    } else {
        sanIn = (*C.uchar)(unsafe.Pointer(nil))
    }
    return int(C.wc_Poly1305Update(poly1305, sanIn, C.word32(inSz)))
}

func Wc_Poly1305Final(poly1305 *C.struct_Poly1305, out []byte) int {
    if len(out) < POLY1305_DIGEST_SIZE {
        return BAD_FUNC_ARG
    }
    return int(C.wc_Poly1305Final(poly1305, (*C.uchar)(unsafe.Pointer(&out[0]))))
}

func Wc_Poly1305_MAC(poly1305 *C.struct_Poly1305, additional []byte, addSz int,
    input []byte, inSz int, tag []byte, tagSz int) int {
    if addSz < 0 || addSz > len(additional) {
        return BAD_FUNC_ARG
    }
    if inSz < 0 || inSz > len(input) {
        return BAD_FUNC_ARG
    }
    if tagSz < 0 || tagSz > len(tag) {
        return BAD_FUNC_ARG
    }
    if tagSz < POLY1305_DIGEST_SIZE {
        return BAD_FUNC_ARG
    }
    var sanAdditional *C.uchar
    if addSz > 0 {
        sanAdditional = (*C.uchar)(unsafe.Pointer(&additional[0]))
    } else {
        sanAdditional = (*C.uchar)(unsafe.Pointer(nil))
    }
    var sanInput *C.uchar
    if inSz > 0 {
        sanInput = (*C.uchar)(unsafe.Pointer(&input[0]))
    } else {
        sanInput = (*C.uchar)(unsafe.Pointer(nil))
    }
    return int(C.wc_Poly1305_MAC(poly1305, sanAdditional, C.word32(addSz),
        sanInput, C.word32(inSz),
        (*C.uchar)(unsafe.Pointer(&tag[0])), C.word32(tagSz)))
}

func Wc_Poly1305_MacCheck(poly1305 *C.struct_Poly1305, additional []byte, addSz int,
    input []byte, inSz int, tag []byte, tagSz int) int {
    if tagSz < 0 || tagSz > len(tag) {
        return BAD_FUNC_ARG
    }
    if tagSz < POLY1305_DIGEST_SIZE {
        return BAD_FUNC_ARG
    }
    var computed [POLY1305_DIGEST_SIZE]byte
    ret := Wc_Poly1305_MAC(poly1305, additional, addSz, input, inSz, computed[:], POLY1305_DIGEST_SIZE)
    if ret != 0 {
        return ret
    }
    if ConstantCompare(computed[:], tag[:tagSz], POLY1305_DIGEST_SIZE) != 1 {
        return BAD_FUNC_ARG
    }
    return 0
}
