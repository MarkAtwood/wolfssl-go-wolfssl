/* hkdf.go
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
// #include <wolfssl/wolfcrypt/hmac.h>
// #ifdef HAVE_HKDF
// static int wc_HKDF_Extract_shim(int hashType,
//                                  const unsigned char* salt, unsigned int saltSz,
//                                  const unsigned char* ikm,  unsigned int ikmSz,
//                                  unsigned char* out) {
//     return wc_HKDF_Extract(hashType,
//                            (const byte*)salt, saltSz,
//                            (const byte*)ikm,  ikmSz,
//                            (byte*)out);
// }
// static int wc_HKDF_Expand_shim(int hashType,
//                                  const unsigned char* prk, unsigned int prkSz,
//                                  const unsigned char* info, unsigned int infoSz,
//                                  unsigned char* out, unsigned int outSz) {
//     return wc_HKDF_Expand(hashType,
//                            (const byte*)prk,  prkSz,
//                            (const byte*)info, infoSz,
//                            (byte*)out, outSz);
// }
// #else
// static int wc_HKDF_Extract_shim(int hashType,
//                                  const unsigned char* salt, unsigned int saltSz,
//                                  const unsigned char* ikm,  unsigned int ikmSz,
//                                  unsigned char* out) {
//     (void)hashType; (void)salt; (void)saltSz;
//     (void)ikm; (void)ikmSz; (void)out;
//     return -174;
// }
// static int wc_HKDF_Expand_shim(int hashType,
//                                  const unsigned char* prk, unsigned int prkSz,
//                                  const unsigned char* info, unsigned int infoSz,
//                                  unsigned char* out, unsigned int outSz) {
//     (void)hashType; (void)prk; (void)prkSz;
//     (void)info; (void)infoSz; (void)out; (void)outSz;
//     return -174;
// }
// #endif /* HAVE_HKDF */
import "C"
import (
	"unsafe"
)

// Wc_HKDF_Extract performs the HKDF extract phase (RFC 5869 §2.2).
// hashType is the HMAC hash algorithm (e.g. WC_SHA256).
// salt may be nil/empty (treated as a zero-filled key of hash length).
// ikm is the input keying material.
// out receives the pseudorandom key (PRK); must be at least WC_MAX_DIGEST_SIZE bytes.
func Wc_HKDF_Extract(hashType int, salt []byte, saltSz int, ikm []byte, ikmSz int, out []byte) int {
	if saltSz < 0 || saltSz > len(salt) {
		return BAD_FUNC_ARG
	}
	if ikmSz < 0 || ikmSz > len(ikm) {
		return BAD_FUNC_ARG
	}
	if len(out) == 0 {
		return BAD_FUNC_ARG
	}

	var saltPtr *C.uchar
	if len(salt) > 0 {
		saltPtr = (*C.uchar)(unsafe.Pointer(&salt[0]))
	}
	var ikmPtr *C.uchar
	if len(ikm) > 0 {
		ikmPtr = (*C.uchar)(unsafe.Pointer(&ikm[0]))
	}
	return int(C.wc_HKDF_Extract_shim(
		C.int(hashType),
		saltPtr, C.uint(saltSz),
		ikmPtr, C.uint(ikmSz),
		(*C.uchar)(unsafe.Pointer(&out[0])),
	))
}

// Wc_HKDF_Expand performs the HKDF expand phase (RFC 5869 §2.3).
// hashType is the HMAC hash algorithm (e.g. WC_SHA256).
// prk is the pseudorandom key produced by Wc_HKDF_Extract.
// info is optional context and application-specific information (may be empty).
// out receives the output keying material; outSz bytes are written.
func Wc_HKDF_Expand(hashType int, prk []byte, prkSz int, info []byte, infoSz int, out []byte, outSz int) int {
	if prkSz < 0 || prkSz > len(prk) {
		return BAD_FUNC_ARG
	}
	if infoSz < 0 || infoSz > len(info) {
		return BAD_FUNC_ARG
	}
	if outSz < 0 || outSz > len(out) {
		return BAD_FUNC_ARG
	}
	if len(prk) == 0 || len(out) == 0 {
		return BAD_FUNC_ARG
	}

	var infoPtr *C.uchar
	if len(info) > 0 {
		infoPtr = (*C.uchar)(unsafe.Pointer(&info[0]))
	}
	return int(C.wc_HKDF_Expand_shim(
		C.int(hashType),
		(*C.uchar)(unsafe.Pointer(&prk[0])), C.uint(prkSz),
		infoPtr, C.uint(infoSz),
		(*C.uchar)(unsafe.Pointer(&out[0])), C.uint(outSz),
	))
}
