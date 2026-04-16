/* curve25519_ext.go
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
// #include <wolfssl/wolfcrypt/curve25519.h>
// #include <wolfssl/wolfcrypt/random.h>
// #ifndef HAVE_CURVE25519
// typedef struct curve25519_key {} curve25519_key;
// static int wc_curve25519_init_ex_stub(curve25519_key* key, void* heap,
//                                       int devId) {
//     (void)key; (void)heap; (void)devId;
//     return -174;
// }
// static int wc_curve25519_shared_secret_ex_stub(curve25519_key* priv,
//                                                curve25519_key* pub,
//                                                byte* out, word32* outlen,
//                                                int endian) {
//     (void)priv; (void)pub; (void)out; (void)outlen; (void)endian;
//     return -174;
// }
// static int wc_curve25519_size_stub(curve25519_key* key) {
//     (void)key;
//     return -174;
// }
// #else
// static int wc_curve25519_init_ex_stub(curve25519_key* key, void* heap,
//                                       int devId) {
//     return wc_curve25519_init_ex(key, heap, devId);
// }
// static int wc_curve25519_shared_secret_ex_stub(curve25519_key* priv,
//                                                curve25519_key* pub,
//                                                byte* out, word32* outlen,
//                                                int endian) {
//     return wc_curve25519_shared_secret_ex(priv, pub, out, outlen, endian);
// }
// static int wc_curve25519_size_stub(curve25519_key* key) {
//     return wc_curve25519_size(key);
// }
// #endif
import "C"
import (
	"unsafe"
)

// Wc_curve25519_init_ex initialises a Curve25519 key with an optional heap
// hint and device ID.  Pass nil for heap and INVALID_DEVID for devId to get
// the same behaviour as Wc_curve25519_init.
func Wc_curve25519_init_ex(key *C.struct_curve25519_key, heap unsafe.Pointer, devId int) int {
	return int(C.wc_curve25519_init_ex_stub(key, heap, C.int(devId)))
}

// Wc_curve25519_shared_secret_ex computes the shared secret from privKey and
// pubKey and writes the result to out.  endian selects the byte order of the
// output: EC25519_LITTLE_ENDIAN (0) or EC25519_BIG_ENDIAN (1).
// outLen must be set to the capacity of out before calling; it is updated to
// the actual shared-secret length on success.
func Wc_curve25519_shared_secret_ex(privKey, pubKey *C.struct_curve25519_key,
	out []byte, outLen *int, endian int) int {
	if outLen == nil || len(out) == 0 || *outLen < 0 || *outLen > len(out) {
		return BAD_FUNC_ARG
	}
	cOutLen := C.word32(*outLen)
	ret := int(C.wc_curve25519_shared_secret_ex_stub(
		privKey, pubKey,
		(*C.uchar)(unsafe.Pointer(&out[0])), &cOutLen,
		C.int(endian),
	))
	*outLen = int(cOutLen)
	return ret
}

// Wc_curve25519_size returns the key size in bytes for the given Curve25519
// key (always 32), or a negative error code on failure.
func Wc_curve25519_size(key *C.struct_curve25519_key) int {
	return int(C.wc_curve25519_size_stub(key))
}
