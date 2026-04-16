/* compress.go
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
// #include <wolfssl/wolfcrypt/compress.h>
// #ifndef HAVE_LIBZ
// #define COMPRESS_FIXED   1
// #define LIBZ_WINBITS_GZIP 16
// int wc_Compress(byte* out, word32 outSz, const byte* in, word32 inSz,
//                 word32 flags) {
//     return -174;
// }
// int wc_Compress_ex(byte* out, word32 outSz, const byte* in, word32 inSz,
//                    word32 flags, word32 windowBits) {
//     return -174;
// }
// int wc_DeCompress(byte* out, word32 outSz, const byte* in, word32 inSz) {
//     return -174;
// }
// int wc_DeCompress_ex(byte* out, word32 outSz, const byte* in, word32 inSz,
//                      int windowBits) {
//     return -174;
// }
// #endif
import "C"
import "unsafe"

const COMPRESS_FIXED    = int(C.COMPRESS_FIXED)
const LIBZ_WINBITS_GZIP = int(C.LIBZ_WINBITS_GZIP)

func Wc_Compress(out []byte, outSz int, in []byte, inSz int, flags int) int {
    if inSz < 0 || inSz > len(in) { return BAD_FUNC_ARG }
    if outSz < 0 || outSz > len(out) { return BAD_FUNC_ARG }
    if inSz == 0 || outSz == 0 { return BAD_FUNC_ARG }
    return int(C.wc_Compress((*C.uchar)(unsafe.Pointer(&out[0])),
               C.word32(outSz),
               (*C.uchar)(unsafe.Pointer(&in[0])),
               C.word32(inSz),
               C.word32(flags)))
}

func Wc_Compress_ex(out []byte, outSz int, in []byte, inSz int, flags int, windowBits int) int {
    if inSz < 0 || inSz > len(in) { return BAD_FUNC_ARG }
    if outSz < 0 || outSz > len(out) { return BAD_FUNC_ARG }
    if inSz == 0 || outSz == 0 { return BAD_FUNC_ARG }
    return int(C.wc_Compress_ex((*C.uchar)(unsafe.Pointer(&out[0])),
               C.word32(outSz),
               (*C.uchar)(unsafe.Pointer(&in[0])),
               C.word32(inSz),
               C.word32(flags),
               C.word32(windowBits)))
}

func Wc_DeCompress(out []byte, outSz int, in []byte, inSz int) int {
    if inSz < 0 || inSz > len(in) { return BAD_FUNC_ARG }
    if outSz < 0 || outSz > len(out) { return BAD_FUNC_ARG }
    if inSz == 0 || outSz == 0 { return BAD_FUNC_ARG }
    return int(C.wc_DeCompress((*C.uchar)(unsafe.Pointer(&out[0])),
               C.word32(outSz),
               (*C.uchar)(unsafe.Pointer(&in[0])),
               C.word32(inSz)))
}

func Wc_DeCompress_ex(out []byte, outSz int, in []byte, inSz int, windowBits int) int {
    if inSz < 0 || inSz > len(in) { return BAD_FUNC_ARG }
    if outSz < 0 || outSz > len(out) { return BAD_FUNC_ARG }
    if inSz == 0 || outSz == 0 { return BAD_FUNC_ARG }
    return int(C.wc_DeCompress_ex((*C.uchar)(unsafe.Pointer(&out[0])),
               C.word32(outSz),
               (*C.uchar)(unsafe.Pointer(&in[0])),
               C.word32(inSz),
               C.int(windowBits)))
}
