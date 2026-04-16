/* arc4.go
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
// #include <wolfssl/wolfcrypt/arc4.h>
// #ifdef NO_RC4
// #define RC4_KEY_SIZE 1
// typedef struct Arc4 {} Arc4;
// int wc_Arc4Init(Arc4* arc4, void* heap, int devId) {
//     return -174;
// }
// void wc_Arc4Free(Arc4* arc4) {
//     return;
// }
// int wc_Arc4SetKey(Arc4* arc4, const byte* key, word32 length) {
//     return -174;
// }
// int wc_Arc4Process(Arc4* arc4, byte* out, const byte* in, word32 length) {
//     return -174;
// }
// #endif
import "C"
import "unsafe"

const RC4_KEY_SIZE = int(C.RC4_KEY_SIZE)

type Arc4 = C.Arc4

func Wc_Arc4Init(arc4 *C.Arc4, devId int) int {
    return int(C.wc_Arc4Init(arc4, unsafe.Pointer(nil), C.int(devId)))
}

func Wc_Arc4Free(arc4 *C.Arc4) {
    C.wc_Arc4Free(arc4)
}

func Wc_Arc4SetKey(arc4 *C.Arc4, key []byte, length int) int {
    if length < 0 || length > len(key) { return BAD_FUNC_ARG }
    if len(key) == 0 { return BAD_FUNC_ARG }
    return int(C.wc_Arc4SetKey(arc4, (*C.uchar)(unsafe.Pointer(&key[0])),
               C.word32(length)))
}

func Wc_Arc4Process(arc4 *C.Arc4, out []byte, in []byte, length int) int {
    if length < 0 || length > len(in) { return BAD_FUNC_ARG }
    if len(out) < length { return BAD_FUNC_ARG }
    if length == 0 { return 0 }
    return int(C.wc_Arc4Process(arc4,
               (*C.uchar)(unsafe.Pointer(&out[0])),
               (*C.uchar)(unsafe.Pointer(&in[0])),
               C.word32(length)))
}
