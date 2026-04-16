/* sm4.go
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

// SM4 is part of the commercial wolfsm extension (https://github.com/wolfSSL/wolfsm).
// The wolfssl/wolfcrypt/sm4.h header in the open-source tree contains only a
// compile-time error directing users to wolfsm. Stubs are provided here so that
// this package builds regardless of whether WOLFSSL_SM4 is defined; callers
// will receive -174 (NOT_COMPILED_IN) from every function.

package wolfSSL

// #cgo CFLAGS: -g -Wall -I/usr/include -I/usr/include/wolfssl -I/usr/local/include -I/usr/local/include/wolfssl
// #cgo LDFLAGS: -L/usr/local/lib -lwolfssl
// #include <wolfssl/options.h>
// #define SM4_KEY_SIZE   16
// #define SM4_IV_SIZE    16
// #define SM4_BLOCK_SIZE 16
// #define GCM_AUTH_TAG_SZ 16
// typedef struct wc_Sm4 { int dummy; } wc_Sm4;
// static int wc_Sm4Init(wc_Sm4* sm4, void* heap, int devId) {
//     (void)sm4; (void)heap; (void)devId; return -174;
// }
// static void wc_Sm4Free(wc_Sm4* sm4) {
//     (void)sm4;
// }
// static int wc_Sm4SetKey(wc_Sm4* sm4, const unsigned char* key,
//                         unsigned int len) {
//     (void)sm4; (void)key; (void)len; return -174;
// }
// static int wc_Sm4SetIV(wc_Sm4* sm4, const unsigned char* iv) {
//     (void)sm4; (void)iv; return -174;
// }
// static int wc_Sm4EcbEncrypt(wc_Sm4* sm4, unsigned char* out,
//                              const unsigned char* in, unsigned int sz) {
//     (void)sm4; (void)out; (void)in; (void)sz; return -174;
// }
// static int wc_Sm4EcbDecrypt(wc_Sm4* sm4, unsigned char* out,
//                              const unsigned char* in, unsigned int sz) {
//     (void)sm4; (void)out; (void)in; (void)sz; return -174;
// }
// static int wc_Sm4CbcEncrypt(wc_Sm4* sm4, unsigned char* out,
//                              const unsigned char* in, unsigned int sz) {
//     (void)sm4; (void)out; (void)in; (void)sz; return -174;
// }
// static int wc_Sm4CbcDecrypt(wc_Sm4* sm4, unsigned char* out,
//                              const unsigned char* in, unsigned int sz) {
//     (void)sm4; (void)out; (void)in; (void)sz; return -174;
// }
// static int wc_Sm4CtrEncrypt(wc_Sm4* sm4, unsigned char* out,
//                              const unsigned char* in, unsigned int sz) {
//     (void)sm4; (void)out; (void)in; (void)sz; return -174;
// }
// static int wc_Sm4GcmSetKey(wc_Sm4* sm4, const unsigned char* key,
//                             unsigned int len) {
//     (void)sm4; (void)key; (void)len; return -174;
// }
// static int wc_Sm4GcmEncrypt(wc_Sm4* sm4, unsigned char* out,
//                              const unsigned char* in, unsigned int sz,
//                              const unsigned char* iv, unsigned int ivSz,
//                              unsigned char* authTag, unsigned int authTagSz,
//                              const unsigned char* authIn,
//                              unsigned int authInSz) {
//     (void)sm4; (void)out; (void)in; (void)sz; (void)iv; (void)ivSz;
//     (void)authTag; (void)authTagSz; (void)authIn; (void)authInSz;
//     return -174;
// }
// static int wc_Sm4GcmDecrypt(wc_Sm4* sm4, unsigned char* out,
//                              const unsigned char* in, unsigned int sz,
//                              const unsigned char* iv, unsigned int ivSz,
//                              const unsigned char* authTag,
//                              unsigned int authTagSz,
//                              const unsigned char* authIn,
//                              unsigned int authInSz) {
//     (void)sm4; (void)out; (void)in; (void)sz; (void)iv; (void)ivSz;
//     (void)authTag; (void)authTagSz; (void)authIn; (void)authInSz;
//     return -174;
// }
import "C"
import "unsafe"

const SM4_KEY_SIZE   = int(C.SM4_KEY_SIZE)
const SM4_IV_SIZE    = int(C.SM4_IV_SIZE)
const SM4_BLOCK_SIZE = int(C.SM4_BLOCK_SIZE)

type Wc_Sm4 = C.struct_wc_Sm4

func Wc_Sm4Init(sm4 *C.struct_wc_Sm4, devId int) int {
    return int(C.wc_Sm4Init(sm4, unsafe.Pointer(nil), C.int(devId)))
}

func Wc_Sm4Free(sm4 *C.struct_wc_Sm4) {
    C.wc_Sm4Free(sm4)
}

func Wc_Sm4SetKey(sm4 *C.struct_wc_Sm4, key []byte, length int) int {
    if length < 0 || length > len(key) { return BAD_FUNC_ARG }
    if len(key) == 0 { return BAD_FUNC_ARG }
    return int(C.wc_Sm4SetKey(sm4, (*C.uchar)(unsafe.Pointer(&key[0])),
               C.uint(length)))
}

func Wc_Sm4SetIV(sm4 *C.struct_wc_Sm4, iv []byte) int {
    if len(iv) < SM4_IV_SIZE { return BAD_FUNC_ARG }
    return int(C.wc_Sm4SetIV(sm4, (*C.uchar)(unsafe.Pointer(&iv[0]))))
}

func Wc_Sm4EcbEncrypt(sm4 *C.struct_wc_Sm4, out []byte, in []byte, sz int) int {
    if sz < 0 || sz > len(in) { return BAD_FUNC_ARG }
    if len(out) < sz { return BAD_FUNC_ARG }
    if sz == 0 { return 0 }
    return int(C.wc_Sm4EcbEncrypt(sm4,
               (*C.uchar)(unsafe.Pointer(&out[0])),
               (*C.uchar)(unsafe.Pointer(&in[0])),
               C.uint(sz)))
}

func Wc_Sm4EcbDecrypt(sm4 *C.struct_wc_Sm4, out []byte, in []byte, sz int) int {
    if sz < 0 || sz > len(in) { return BAD_FUNC_ARG }
    if len(out) < sz { return BAD_FUNC_ARG }
    if sz == 0 { return 0 }
    return int(C.wc_Sm4EcbDecrypt(sm4,
               (*C.uchar)(unsafe.Pointer(&out[0])),
               (*C.uchar)(unsafe.Pointer(&in[0])),
               C.uint(sz)))
}

func Wc_Sm4CbcEncrypt(sm4 *C.struct_wc_Sm4, out []byte, in []byte, sz int) int {
    if sz < 0 || sz > len(in) { return BAD_FUNC_ARG }
    if len(out) < sz { return BAD_FUNC_ARG }
    if sz == 0 { return 0 }
    return int(C.wc_Sm4CbcEncrypt(sm4,
               (*C.uchar)(unsafe.Pointer(&out[0])),
               (*C.uchar)(unsafe.Pointer(&in[0])),
               C.uint(sz)))
}

func Wc_Sm4CbcDecrypt(sm4 *C.struct_wc_Sm4, out []byte, in []byte, sz int) int {
    if sz < 0 || sz > len(in) { return BAD_FUNC_ARG }
    if len(out) < sz { return BAD_FUNC_ARG }
    if sz == 0 { return 0 }
    return int(C.wc_Sm4CbcDecrypt(sm4,
               (*C.uchar)(unsafe.Pointer(&out[0])),
               (*C.uchar)(unsafe.Pointer(&in[0])),
               C.uint(sz)))
}

func Wc_Sm4CtrEncrypt(sm4 *C.struct_wc_Sm4, out []byte, in []byte, sz int) int {
    if sz < 0 || sz > len(in) { return BAD_FUNC_ARG }
    if len(out) < sz { return BAD_FUNC_ARG }
    if sz == 0 { return 0 }
    return int(C.wc_Sm4CtrEncrypt(sm4,
               (*C.uchar)(unsafe.Pointer(&out[0])),
               (*C.uchar)(unsafe.Pointer(&in[0])),
               C.uint(sz)))
}

func Wc_Sm4GcmSetKey(sm4 *C.struct_wc_Sm4, key []byte, length int) int {
    if length < 0 || length > len(key) { return BAD_FUNC_ARG }
    if len(key) == 0 { return BAD_FUNC_ARG }
    return int(C.wc_Sm4GcmSetKey(sm4, (*C.uchar)(unsafe.Pointer(&key[0])),
               C.uint(length)))
}

func Wc_Sm4GcmEncrypt(sm4 *C.struct_wc_Sm4, out []byte, in []byte, sz int,
    iv []byte, ivSz int, authTag []byte, authTagSz int,
    authIn []byte, authInSz int) int {
    if sz < 0 || sz > len(in) { return BAD_FUNC_ARG }
    if len(out) < sz { return BAD_FUNC_ARG }
    if ivSz < 0 || ivSz > len(iv) { return BAD_FUNC_ARG }
    if authTagSz < 0 || authTagSz > len(authTag) { return BAD_FUNC_ARG }
    if authInSz < 0 || authInSz > len(authIn) { return BAD_FUNC_ARG }
    var outPtr, inPtr, ivPtr, authTagPtr, authInPtr *C.uchar
    if sz > 0 {
        outPtr = (*C.uchar)(unsafe.Pointer(&out[0]))
        inPtr  = (*C.uchar)(unsafe.Pointer(&in[0]))
    }
    if ivSz > 0 {
        ivPtr = (*C.uchar)(unsafe.Pointer(&iv[0]))
    }
    if authTagSz > 0 {
        authTagPtr = (*C.uchar)(unsafe.Pointer(&authTag[0]))
    }
    if authInSz > 0 {
        authInPtr = (*C.uchar)(unsafe.Pointer(&authIn[0]))
    }
    return int(C.wc_Sm4GcmEncrypt(sm4, outPtr, inPtr, C.uint(sz),
               ivPtr, C.uint(ivSz), authTagPtr, C.uint(authTagSz),
               authInPtr, C.uint(authInSz)))
}

func Wc_Sm4GcmDecrypt(sm4 *C.struct_wc_Sm4, out []byte, in []byte, sz int,
    iv []byte, ivSz int, authTag []byte, authTagSz int,
    authIn []byte, authInSz int) int {
    if sz < 0 || sz > len(in) { return BAD_FUNC_ARG }
    if len(out) < sz { return BAD_FUNC_ARG }
    if ivSz < 0 || ivSz > len(iv) { return BAD_FUNC_ARG }
    if authTagSz < 0 || authTagSz > len(authTag) { return BAD_FUNC_ARG }
    if authInSz < 0 || authInSz > len(authIn) { return BAD_FUNC_ARG }
    var outPtr, inPtr, ivPtr, authTagPtr, authInPtr *C.uchar
    if sz > 0 {
        outPtr = (*C.uchar)(unsafe.Pointer(&out[0]))
        inPtr  = (*C.uchar)(unsafe.Pointer(&in[0]))
    }
    if ivSz > 0 {
        ivPtr = (*C.uchar)(unsafe.Pointer(&iv[0]))
    }
    if authTagSz > 0 {
        authTagPtr = (*C.uchar)(unsafe.Pointer(&authTag[0]))
    }
    if authInSz > 0 {
        authInPtr = (*C.uchar)(unsafe.Pointer(&authIn[0]))
    }
    return int(C.wc_Sm4GcmDecrypt(sm4, outPtr, inPtr, C.uint(sz),
               ivPtr, C.uint(ivSz), authTagPtr, C.uint(authTagSz),
               authInPtr, C.uint(authInSz)))
}
