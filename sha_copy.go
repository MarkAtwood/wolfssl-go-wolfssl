/* sha_copy.go
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
// #include <wolfssl/wolfcrypt/sha256.h>
// #include <wolfssl/wolfcrypt/sha512.h>
// #include <wolfssl/wolfcrypt/sha3.h>
//
// /* --- SHA-256 copy --- */
// #ifndef NO_SHA256
// static int wc_Sha256Copy_shim(wc_Sha256* src, wc_Sha256* dst) {
//     return wc_Sha256Copy(src, dst);
// }
// #else
// static int wc_Sha256Copy_shim(void* src, void* dst) {
//     (void)src; (void)dst; return -174;
// }
// #endif
//
// /* --- SHA-224 copy --- */
// #if defined(WOLFSSL_SHA224) && !defined(NO_SHA256)
// static int wc_Sha224Copy_shim(wc_Sha224* src, wc_Sha224* dst) {
//     return wc_Sha224Copy(src, dst);
// }
// #else
// static int wc_Sha224Copy_shim(void* src, void* dst) {
//     (void)src; (void)dst; return -174;
// }
// #endif
//
// /* --- SHA-384 copy --- */
// #ifdef WOLFSSL_SHA384
// static int wc_Sha384Copy_shim(wc_Sha384* src, wc_Sha384* dst) {
//     return wc_Sha384Copy(src, dst);
// }
// #else
// static int wc_Sha384Copy_shim(void* src, void* dst) {
//     (void)src; (void)dst; return -174;
// }
// #endif
//
// /* --- SHA-512 copy --- */
// #ifdef WOLFSSL_SHA512
// static int wc_Sha512Copy_shim(wc_Sha512* src, wc_Sha512* dst) {
//     return wc_Sha512Copy(src, dst);
// }
// #else
// static int wc_Sha512Copy_shim(void* src, void* dst) {
//     (void)src; (void)dst; return -174;
// }
// #endif
//
// /* --- SHA3-256 copy --- */
// #ifdef WOLFSSL_SHA3
// static int wc_Sha3_256_Copy_shim(wc_Sha3* src, wc_Sha3* dst) {
//     return wc_Sha3_256_Copy(src, dst);
// }
// #else
// static int wc_Sha3_256_Copy_shim(void* src, void* dst) {
//     (void)src; (void)dst; return -174;
// }
// #endif
import "C"

// Wc_Sha256Copy duplicates a mid-stream SHA-256 state from src into dst.
// Both src and dst must have been initialised with Wc_InitSha256_ex.
func Wc_Sha256Copy(src *C.struct_wc_Sha256, dst *C.struct_wc_Sha256) int {
    return int(C.wc_Sha256Copy_shim(src, dst))
}

// Wc_Sha224Copy duplicates a mid-stream SHA-224 state from src into dst.
// Both src and dst must have been initialised with wc_InitSha224_ex.
// Returns -174 if wolfSSL was built without WOLFSSL_SHA224.
func Wc_Sha224Copy(src *C.struct_wc_Sha256, dst *C.struct_wc_Sha256) int {
    return int(C.wc_Sha224Copy_shim(src, dst))
}

// Wc_Sha384Copy duplicates a mid-stream SHA-384 state from src into dst.
// Both src and dst must have been initialised with wc_InitSha384_ex.
// Returns -174 if wolfSSL was built without WOLFSSL_SHA384.
func Wc_Sha384Copy(src *C.struct_wc_Sha512, dst *C.struct_wc_Sha512) int {
    return int(C.wc_Sha384Copy_shim(src, dst))
}

// Wc_Sha512Copy duplicates a mid-stream SHA-512 state from src into dst.
// Both src and dst must have been initialised with wc_InitSha512_ex.
// Returns -174 if wolfSSL was built without WOLFSSL_SHA512.
func Wc_Sha512Copy(src *C.struct_wc_Sha512, dst *C.struct_wc_Sha512) int {
    return int(C.wc_Sha512Copy_shim(src, dst))
}

// Wc_Sha3_256_Copy duplicates a mid-stream SHA3-256 state from src into dst.
// Both src and dst must have been initialised with wc_InitSha3_256.
// Returns -174 if wolfSSL was built without WOLFSSL_SHA3.
func Wc_Sha3_256_Copy(src *C.struct_wc_Sha3, dst *C.struct_wc_Sha3) int {
    return int(C.wc_Sha3_256_Copy_shim(src, dst))
}
