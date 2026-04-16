/* aes_cts.go
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
// #include <wolfssl/wolfcrypt/aes.h>
// #ifndef WOLFSSL_AES_CTS
// int wc_AesCtsEncrypt(const byte* key, word32 keySz, byte* out,
//                      const byte* in, word32 inSz, const byte* iv) {
//     return -174;
// }
// int wc_AesCtsDecrypt(const byte* key, word32 keySz, byte* out,
//                      const byte* in, word32 inSz, const byte* iv) {
//     return -174;
// }
// int wc_AesCtsEncryptUpdate(Aes* aes, byte* out, word32* outSz,
//                             const byte* in, word32 inSz) {
//     return -174;
// }
// int wc_AesCtsDecryptUpdate(Aes* aes, byte* out, word32* outSz,
//                             const byte* in, word32 inSz) {
//     return -174;
// }
// int wc_AesCtsEncryptFinal(Aes* aes, byte* out, word32* outSz) {
//     return -174;
// }
// int wc_AesCtsDecryptFinal(Aes* aes, byte* out, word32* outSz) {
//     return -174;
// }
// #endif
import "C"
import "unsafe"

func Wc_AesCtsEncrypt(key []byte, keySz int, out []byte, in []byte, inSz int, iv []byte) int {
    if keySz < 0 || keySz > len(key) { return BAD_FUNC_ARG }
    if inSz < 0 || inSz > len(in) { return BAD_FUNC_ARG }
    if len(out) < inSz { return BAD_FUNC_ARG }
    if len(key) == 0 || len(iv) < AES_IV_SIZE { return BAD_FUNC_ARG }
    if inSz == 0 { return 0 }
    return int(C.wc_AesCtsEncrypt((*C.uchar)(unsafe.Pointer(&key[0])),
               C.word32(keySz),
               (*C.uchar)(unsafe.Pointer(&out[0])),
               (*C.uchar)(unsafe.Pointer(&in[0])),
               C.word32(inSz),
               (*C.uchar)(unsafe.Pointer(&iv[0]))))
}

func Wc_AesCtsDecrypt(key []byte, keySz int, out []byte, in []byte, inSz int, iv []byte) int {
    if keySz < 0 || keySz > len(key) { return BAD_FUNC_ARG }
    if inSz < 0 || inSz > len(in) { return BAD_FUNC_ARG }
    if len(out) < inSz { return BAD_FUNC_ARG }
    if len(key) == 0 || len(iv) < AES_IV_SIZE { return BAD_FUNC_ARG }
    if inSz == 0 { return 0 }
    return int(C.wc_AesCtsDecrypt((*C.uchar)(unsafe.Pointer(&key[0])),
               C.word32(keySz),
               (*C.uchar)(unsafe.Pointer(&out[0])),
               (*C.uchar)(unsafe.Pointer(&in[0])),
               C.word32(inSz),
               (*C.uchar)(unsafe.Pointer(&iv[0]))))
}

func Wc_AesCtsEncryptUpdate(aes *C.struct_Aes, out []byte, outSz *int, in []byte, inSz int) int {
    if inSz < 0 || inSz > len(in) { return BAD_FUNC_ARG }
    if outSz == nil { return BAD_FUNC_ARG }
    var outPtr *C.uchar
    if len(out) > 0 {
        outPtr = (*C.uchar)(unsafe.Pointer(&out[0]))
    }
    var inPtr *C.uchar
    if len(in) > 0 {
        inPtr = (*C.uchar)(unsafe.Pointer(&in[0]))
    }
    cOutSz := C.word32(*outSz)
    ret := int(C.wc_AesCtsEncryptUpdate(aes, outPtr, &cOutSz, inPtr, C.word32(inSz)))
    *outSz = int(cOutSz)
    return ret
}

func Wc_AesCtsDecryptUpdate(aes *C.struct_Aes, out []byte, outSz *int, in []byte, inSz int) int {
    if inSz < 0 || inSz > len(in) { return BAD_FUNC_ARG }
    if outSz == nil { return BAD_FUNC_ARG }
    var outPtr *C.uchar
    if len(out) > 0 {
        outPtr = (*C.uchar)(unsafe.Pointer(&out[0]))
    }
    var inPtr *C.uchar
    if len(in) > 0 {
        inPtr = (*C.uchar)(unsafe.Pointer(&in[0]))
    }
    cOutSz := C.word32(*outSz)
    ret := int(C.wc_AesCtsDecryptUpdate(aes, outPtr, &cOutSz, inPtr, C.word32(inSz)))
    *outSz = int(cOutSz)
    return ret
}

func Wc_AesCtsEncryptFinal(aes *C.struct_Aes, out []byte, outSz *int) int {
    if outSz == nil { return BAD_FUNC_ARG }
    var outPtr *C.uchar
    if len(out) > 0 {
        outPtr = (*C.uchar)(unsafe.Pointer(&out[0]))
    }
    cOutSz := C.word32(*outSz)
    ret := int(C.wc_AesCtsEncryptFinal(aes, outPtr, &cOutSz))
    *outSz = int(cOutSz)
    return ret
}

func Wc_AesCtsDecryptFinal(aes *C.struct_Aes, out []byte, outSz *int) int {
    if outSz == nil { return BAD_FUNC_ARG }
    var outPtr *C.uchar
    if len(out) > 0 {
        outPtr = (*C.uchar)(unsafe.Pointer(&out[0]))
    }
    cOutSz := C.word32(*outSz)
    ret := int(C.wc_AesCtsDecryptFinal(aes, outPtr, &cOutSz))
    *outSz = int(cOutSz)
    return ret
}
