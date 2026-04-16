/* pkcs7.go
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
// #include <wolfssl/wolfcrypt/pkcs7.h>
//
// /* ---- wc_PKCS7_Init ------------------------------------------------------ */
//
// static int go_wc_PKCS7_Init(wc_PKCS7* pkcs7, void* heap, int devId) {
// #ifdef HAVE_PKCS7
//     return wc_PKCS7_Init(pkcs7, heap, devId);
// #else
//     (void)pkcs7; (void)heap; (void)devId;
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* ---- wc_PKCS7_InitWithCert ---------------------------------------------- */
//
// static int go_wc_PKCS7_InitWithCert(wc_PKCS7* pkcs7, byte* der,
//         word32 derSz) {
// #ifdef HAVE_PKCS7
//     return wc_PKCS7_InitWithCert(pkcs7, der, derSz);
// #else
//     (void)pkcs7; (void)der; (void)derSz;
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* ---- wc_PKCS7_Free ------------------------------------------------------ */
//
// static void go_wc_PKCS7_Free(wc_PKCS7* pkcs7) {
// #ifdef HAVE_PKCS7
//     wc_PKCS7_Free(pkcs7);
// #else
//     (void)pkcs7;
// #endif
// }
//
// /* ---- wc_PKCS7_EncodeData ------------------------------------------------ */
//
// static int go_wc_PKCS7_EncodeData(wc_PKCS7* pkcs7, byte* output,
//         word32 outputSz) {
// #ifdef HAVE_PKCS7
//     return wc_PKCS7_EncodeData(pkcs7, output, outputSz);
// #else
//     (void)pkcs7; (void)output; (void)outputSz;
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* ---- wc_PKCS7_VerifySignedData ------------------------------------------ */
//
// static int go_wc_PKCS7_VerifySignedData(wc_PKCS7* pkcs7, byte* pkiMsg,
//         word32 pkiMsgSz) {
// #ifdef HAVE_PKCS7
//     return wc_PKCS7_VerifySignedData(pkcs7, pkiMsg, pkiMsgSz);
// #else
//     (void)pkcs7; (void)pkiMsg; (void)pkiMsgSz;
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* ---- wc_PKCS7_EncodeEnvelopedData --------------------------------------- */
//
// static int go_wc_PKCS7_EncodeEnvelopedData(wc_PKCS7* pkcs7, byte* output,
//         word32 outputSz) {
// #ifdef HAVE_PKCS7
//     return wc_PKCS7_EncodeEnvelopedData(pkcs7, output, outputSz);
// #else
//     (void)pkcs7; (void)output; (void)outputSz;
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* ---- wc_PKCS7_DecodeEnvelopedData --------------------------------------- */
//
// static int go_wc_PKCS7_DecodeEnvelopedData(wc_PKCS7* pkcs7, byte* pkiMsg,
//         word32 pkiMsgSz, byte* output, word32 outputSz) {
// #ifdef HAVE_PKCS7
//     return wc_PKCS7_DecodeEnvelopedData(pkcs7, pkiMsg, pkiMsgSz,
//                                         output, outputSz);
// #else
//     (void)pkcs7; (void)pkiMsg; (void)pkiMsgSz; (void)output; (void)outputSz;
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* ---- wc_PKCS7_SetKey ---------------------------------------------------- */
//
// static int go_wc_PKCS7_SetKey(wc_PKCS7* pkcs7, byte* key, word32 keySz) {
// #ifdef HAVE_PKCS7
//     return wc_PKCS7_SetKey(pkcs7, key, keySz);
// #else
//     (void)pkcs7; (void)key; (void)keySz;
//     return NOT_COMPILED_IN;
// #endif
// }
import "C"
import (
	"unsafe"
)

// WC_PKCS7 is the wolfcrypt PKCS#7 message structure.
type WC_PKCS7 = C.struct_wc_PKCS7

// Wc_PKCS7_Init initialises a caller-allocated WC_PKCS7 structure.
//
// heap and devId follow the standard wolfcrypt heap/device conventions
// (pass nil/INVALID_DEVID for defaults).
//
// Returns 0 on success, negative error code on failure.
// Requires wolfSSL built with HAVE_PKCS7.
func Wc_PKCS7_Init(pkcs7 *WC_PKCS7, heap unsafe.Pointer, devId int) int {
	return int(C.go_wc_PKCS7_Init((*C.struct_wc_PKCS7)(pkcs7), heap, C.int(devId)))
}

// Wc_PKCS7_InitWithCert initialises a caller-allocated WC_PKCS7 and attaches
// a signing certificate in DER format. der may be nil with derSz 0 to skip
// certificate attachment (cert can be set later via field assignment).
//
// Returns 0 on success, negative error code on failure.
// Requires wolfSSL built with HAVE_PKCS7.
func Wc_PKCS7_InitWithCert(pkcs7 *WC_PKCS7, der []byte, derSz int) int {
	if derSz < 0 || derSz > len(der) {
		return BAD_FUNC_ARG
	}
	var derPtr *C.uchar
	if derSz > 0 {
		derPtr = (*C.uchar)(unsafe.Pointer(&der[0]))
	}
	return int(C.go_wc_PKCS7_InitWithCert(
		(*C.struct_wc_PKCS7)(pkcs7), derPtr, C.word32(derSz)))
}

// Wc_PKCS7_Free releases resources held by pkcs7. The struct memory itself is
// not freed (it is caller-managed).
// Requires wolfSSL built with HAVE_PKCS7.
func Wc_PKCS7_Free(pkcs7 *WC_PKCS7) {
	C.go_wc_PKCS7_Free((*C.struct_wc_PKCS7)(pkcs7))
}

// Wc_PKCS7_EncodeData encodes a PKCS#7 Data content-type message into output.
// The pkcs7 struct must have the content fields set before calling.
//
// Returns the number of bytes written on success (> 0), or a negative error
// code on failure.
// Requires wolfSSL built with HAVE_PKCS7.
func Wc_PKCS7_EncodeData(pkcs7 *WC_PKCS7, output []byte, outputSz int) int {
	if outputSz < 0 || outputSz > len(output) {
		return BAD_FUNC_ARG
	}
	if len(output) == 0 {
		return BAD_FUNC_ARG
	}
	return int(C.go_wc_PKCS7_EncodeData(
		(*C.struct_wc_PKCS7)(pkcs7),
		(*C.uchar)(unsafe.Pointer(&output[0])),
		C.word32(outputSz)))
}

// Wc_PKCS7_VerifySignedData verifies a DER-encoded PKCS#7 SignedData message.
// pkiMsg contains the full CMS/PKCS#7 bundle to verify.
//
// Returns 0 on success (signature valid), negative error code on failure.
// Requires wolfSSL built with HAVE_PKCS7.
func Wc_PKCS7_VerifySignedData(pkcs7 *WC_PKCS7, pkiMsg []byte, pkiMsgSz int) int {
	if pkiMsgSz < 0 || pkiMsgSz > len(pkiMsg) {
		return BAD_FUNC_ARG
	}
	if len(pkiMsg) == 0 {
		return BAD_FUNC_ARG
	}
	return int(C.go_wc_PKCS7_VerifySignedData(
		(*C.struct_wc_PKCS7)(pkcs7),
		(*C.uchar)(unsafe.Pointer(&pkiMsg[0])),
		C.word32(pkiMsgSz)))
}

// Wc_PKCS7_EncodeEnvelopedData encodes a PKCS#7 EnvelopedData message into
// output. The pkcs7 struct must have recipient info and content set before
// calling.
//
// Returns the number of bytes written on success (> 0), or a negative error
// code on failure.
// Requires wolfSSL built with HAVE_PKCS7.
func Wc_PKCS7_EncodeEnvelopedData(pkcs7 *WC_PKCS7, output []byte, outputSz int) int {
	if outputSz < 0 || outputSz > len(output) {
		return BAD_FUNC_ARG
	}
	if len(output) == 0 {
		return BAD_FUNC_ARG
	}
	return int(C.go_wc_PKCS7_EncodeEnvelopedData(
		(*C.struct_wc_PKCS7)(pkcs7),
		(*C.uchar)(unsafe.Pointer(&output[0])),
		C.word32(outputSz)))
}

// Wc_PKCS7_DecodeEnvelopedData decrypts a DER-encoded PKCS#7 EnvelopedData
// message and writes the plaintext into output.
//
// Returns the number of decrypted bytes written on success (> 0), or a
// negative error code on failure.
// Requires wolfSSL built with HAVE_PKCS7.
func Wc_PKCS7_DecodeEnvelopedData(pkcs7 *WC_PKCS7, pkiMsg []byte, pkiMsgSz int, output []byte, outputSz int) int {
	if pkiMsgSz < 0 || pkiMsgSz > len(pkiMsg) {
		return BAD_FUNC_ARG
	}
	if outputSz < 0 || outputSz > len(output) {
		return BAD_FUNC_ARG
	}
	if len(pkiMsg) == 0 || len(output) == 0 {
		return BAD_FUNC_ARG
	}
	return int(C.go_wc_PKCS7_DecodeEnvelopedData(
		(*C.struct_wc_PKCS7)(pkcs7),
		(*C.uchar)(unsafe.Pointer(&pkiMsg[0])), C.word32(pkiMsgSz),
		(*C.uchar)(unsafe.Pointer(&output[0])), C.word32(outputSz)))
}

// Wc_PKCS7_SetKey sets the symmetric content-encryption key on pkcs7.
// Used with KEKRI (key-encryption-key) recipient info.
//
// Returns 0 on success, negative error code on failure.
// Requires wolfSSL built with HAVE_PKCS7.
func Wc_PKCS7_SetKey(pkcs7 *WC_PKCS7, key []byte, keySz int) int {
	if keySz < 0 || keySz > len(key) {
		return BAD_FUNC_ARG
	}
	if len(key) == 0 {
		return BAD_FUNC_ARG
	}
	return int(C.go_wc_PKCS7_SetKey(
		(*C.struct_wc_PKCS7)(pkcs7),
		(*C.uchar)(unsafe.Pointer(&key[0])),
		C.word32(keySz)))
}
