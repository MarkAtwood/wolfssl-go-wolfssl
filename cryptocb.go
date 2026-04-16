/* cryptocb.go
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
// #include <wolfssl/wolfcrypt/cryptocb.h>
//
// #ifndef WOLF_CRYPTO_CB
// static int wc_go_CryptoCb_RegisterDevice(int devId, void* cb, void* ctx) {
//     (void)devId; (void)cb; (void)ctx; return -174;
// }
// static void wc_go_CryptoCb_UnRegisterDevice(int devId) { (void)devId; }
// static int wc_go_CryptoCb_DefaultDevID(void) { return -174; }
// #else
// // Shim: accept the callback as void* to avoid CGO function-pointer
// // restrictions; cast to CryptoDevCallbackFunc internally.
// static int wc_go_CryptoCb_RegisterDevice(int devId, void* cb, void* ctx) {
//     return wc_CryptoCb_RegisterDevice(devId, (CryptoDevCallbackFunc)cb, ctx);
// }
// static void wc_go_CryptoCb_UnRegisterDevice(int devId) {
//     wc_CryptoCb_UnRegisterDevice(devId);
// }
// static int wc_go_CryptoCb_DefaultDevID(void) {
//     return wc_CryptoCb_DefaultDevID();
// }
// #endif
import "C"
import "unsafe"

// Wc_CryptoCb_RegisterDevice registers a hardware crypto callback for the
// given devId.  cb must be a C function pointer of type
// CryptoDevCallbackFunc, passed as an unsafe.Pointer.  ctx is an arbitrary
// context pointer forwarded to the callback on each call.
// Returns 0 on success, negative on error.  Returns -174 when wolfSSL was
// built without WOLF_CRYPTO_CB.
func Wc_CryptoCb_RegisterDevice(devId int, cb unsafe.Pointer, ctx unsafe.Pointer) int {
    return int(C.wc_go_CryptoCb_RegisterDevice(C.int(devId), cb, ctx))
}

// Wc_CryptoCb_UnRegisterDevice removes the hardware crypto callback
// registered for devId.
func Wc_CryptoCb_UnRegisterDevice(devId int) {
    C.wc_go_CryptoCb_UnRegisterDevice(C.int(devId))
}

// Wc_CryptoCb_DefaultDevID returns the default crypto callback device ID, or
// -174 when wolfSSL was built without WOLF_CRYPTO_CB.
func Wc_CryptoCb_DefaultDevID() int {
    return int(C.wc_go_CryptoCb_DefaultDevID())
}
