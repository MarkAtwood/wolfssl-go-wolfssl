/* logging.go
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
// #include <wolfssl/wolfcrypt/logging.h>
//
// // Shim to call wolfSSL_SetLoggingCb with a function pointer supplied as a
// // plain void* to avoid CGO's restriction on passing Go function values.
// // The caller must supply a C function pointer cast to void*.
// static int wc_go_SetLoggingCb(void* cb) {
//     return wolfSSL_SetLoggingCb((wolfSSL_Logging_cb)cb);
// }
//
import "C"
import "unsafe"

// WolfSSL_SetLoggingCb installs a custom log callback.  cb must be a C
// function pointer of type wolfSSL_Logging_cb, passed as an unsafe.Pointer.
// The callback signature is:
//   void my_cb(const int logLevel, const char *const logMessage)
// Returns 0 on success, negative on error (e.g. -174 if logging not compiled
// in).
func WolfSSL_SetLoggingCb(cb unsafe.Pointer) int {
    return int(C.wc_go_SetLoggingCb(cb))
}
