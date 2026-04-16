/* siphash.go
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

// #cgo CFLAGS: -g -Wall -I/usr/include -I/usr/include/wolfssl -I/usr/local/include -I/usr/local/include/wolfssl
// #cgo LDFLAGS: -L/usr/local/lib -lwolfssl
// #include <wolfssl/options.h>
// #include <wolfssl/wolfcrypt/siphash.h>
// #ifndef WOLFSSL_SIPHASH
// #define SIPHASH_KEY_SIZE    1
// #define SIPHASH_MAC_SIZE_8  1
// #define SIPHASH_MAC_SIZE_16 1
// typedef struct SipHash {} SipHash;
// int wc_InitSipHash(SipHash* sipHash, const unsigned char* key,
//                    unsigned char outSz) {
//     return -174;
// }
// int wc_SipHashUpdate(SipHash* sipHash, const unsigned char* in,
//                      word32 inSz) {
//     return -174;
// }
// int wc_SipHashFinal(SipHash* sipHash, unsigned char* out,
//                     unsigned char outSz) {
//     return -174;
// }
// int wc_SipHash(const unsigned char* key, const unsigned char* in,
//                word32 inSz, unsigned char* out, unsigned char outSz) {
//     return -174;
// }
// #endif
import "C"
import "unsafe"

const SIPHASH_KEY_SIZE    = int(C.SIPHASH_KEY_SIZE)
const SIPHASH_MAC_SIZE_8  = int(C.SIPHASH_MAC_SIZE_8)
const SIPHASH_MAC_SIZE_16 = int(C.SIPHASH_MAC_SIZE_16)

type SipHash = C.SipHash

func Wc_InitSipHash(sipHash *C.SipHash, key []byte, outSz int) int {
    if len(key) < SIPHASH_KEY_SIZE { return BAD_FUNC_ARG }
    return int(C.wc_InitSipHash(sipHash, (*C.uchar)(unsafe.Pointer(&key[0])),
               C.uchar(outSz)))
}

func Wc_SipHashUpdate(sipHash *C.SipHash, in []byte, inSz int) int {
    if inSz < 0 || inSz > len(in) { return BAD_FUNC_ARG }
    var inPtr *C.uchar
    if len(in) > 0 {
        inPtr = (*C.uchar)(unsafe.Pointer(&in[0]))
    }
    return int(C.wc_SipHashUpdate(sipHash, inPtr, C.word32(inSz)))
}

func Wc_SipHashFinal(sipHash *C.SipHash, out []byte, outSz int) int {
    if len(out) < outSz { return BAD_FUNC_ARG }
    if len(out) == 0 { return BAD_FUNC_ARG }
    return int(C.wc_SipHashFinal(sipHash, (*C.uchar)(unsafe.Pointer(&out[0])),
               C.uchar(outSz)))
}

func Wc_SipHash(key []byte, in []byte, inSz int, out []byte, outSz int) int {
    if len(key) < SIPHASH_KEY_SIZE { return BAD_FUNC_ARG }
    if inSz < 0 || inSz > len(in) { return BAD_FUNC_ARG }
    if len(out) < outSz { return BAD_FUNC_ARG }
    var inPtr *C.uchar
    if len(in) > 0 {
        inPtr = (*C.uchar)(unsafe.Pointer(&in[0]))
    }
    return int(C.wc_SipHash((*C.uchar)(unsafe.Pointer(&key[0])),
               inPtr, C.word32(inSz),
               (*C.uchar)(unsafe.Pointer(&out[0])),
               C.uchar(outSz)))
}
