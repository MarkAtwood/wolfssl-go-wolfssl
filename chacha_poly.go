/* chacha_poly.go
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
// #include <wolfssl/wolfcrypt/chacha20_poly1305.h>
// #ifndef HAVE_CHACHA
// #define CHACHA20_POLY1305_AEAD_KEYSIZE 1
// #define CHACHA20_POLY1305_AEAD_IV_SIZE 1
// #define CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE 1
// #define XCHACHA20_POLY1305_AEAD_NONCE_SIZE  1
// int wc_ChaCha20Poly1305_Encrypt(
//                 byte inKey[CHACHA20_POLY1305_AEAD_KEYSIZE],
//                 byte inIV[CHACHA20_POLY1305_AEAD_IV_SIZE],
//                 byte* inAAD, word32 inAADLen,
//                 byte* inPlaintext, word32 inPlaintextLen,
//                byte* outCiphertext,
//                byte outAuthTag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE]) {
//      return -174;
// }
// int wc_ChaCha20Poly1305_Decrypt(
//                 byte inKey[CHACHA20_POLY1305_AEAD_KEYSIZE],
//                 byte inIV[CHACHA20_POLY1305_AEAD_IV_SIZE],
//                 byte* inAAD, word32 inAADLen,
//                 byte* inCiphertext, word32 inCiphertextLen,
//                 byte inAuthTag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE],
//                byte* outPlaintext) {
//      return -174;
// }
// #endif
// #if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
// static int wc_ChaCha20Poly1305_Init_shim(ChaChaPoly_Aead* aead,
//     const byte* inKey, const byte* inIV, int isEncrypt) {
//     return wc_ChaCha20Poly1305_Init(aead, inKey, inIV, isEncrypt);
// }
// static int wc_ChaCha20Poly1305_Final_shim(ChaChaPoly_Aead* aead,
//     byte* outAuthTag) {
//     return wc_ChaCha20Poly1305_Final(aead, outAuthTag);
// }
// #else
// typedef struct ChaChaPoly_Aead {} ChaChaPoly_Aead;
// static int wc_ChaCha20Poly1305_Init_shim(ChaChaPoly_Aead* aead,
//     const byte* inKey, const byte* inIV, int isEncrypt) {
//     (void)aead; (void)inKey; (void)inIV; (void)isEncrypt;
//     return -174;
// }
// static int wc_ChaCha20Poly1305_UpdateAad(ChaChaPoly_Aead* aead,
//     const byte* inAAD, word32 inAADLen) {
//     (void)aead; (void)inAAD; (void)inAADLen;
//     return -174;
// }
// static int wc_ChaCha20Poly1305_UpdateData(ChaChaPoly_Aead* aead,
//     const byte* inData, byte* outData, word32 dataLen) {
//     (void)aead; (void)inData; (void)outData; (void)dataLen;
//     return -174;
// }
// static int wc_ChaCha20Poly1305_Final_shim(ChaChaPoly_Aead* aead,
//     byte* outAuthTag) {
//     (void)aead; (void)outAuthTag;
//     return -174;
// }
// #endif
// #ifndef HAVE_XCHACHA
// int wc_XChaCha20Poly1305_Encrypt(
//    byte *dst, size_t dst_space,
//    const byte *src, size_t src_len,
//    const byte *ad, size_t ad_len,
//    const byte *nonce, size_t nonce_len,
//    const byte *key, size_t key_len) {
//      return -174;
// }
// int wc_XChaCha20Poly1305_Decrypt(
//    byte *dst, size_t dst_space,
//    const byte *src, size_t src_len,
//    const byte *ad, size_t ad_len,
//    const byte *nonce, size_t nonce_len,
//    const byte *key, size_t key_len) {
//      return -174;
// }
// #endif
import "C"
import (
	"unsafe"
)

const CHACHA20_POLY1305_AEAD_KEYSIZE = int(C.CHACHA20_POLY1305_AEAD_KEYSIZE)
const CHACHA20_POLY1305_AEAD_IV_SIZE = int(C.CHACHA20_POLY1305_AEAD_IV_SIZE)
const CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE = int(C.CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE)
const XCHACHA20_POLY1305_AEAD_NONCE_SIZE = int(C.XCHACHA20_POLY1305_AEAD_NONCE_SIZE)
const CHACHA20_POLY1305_AEAD_NONCE_SIZE = int(C.CHACHA20_POLY1305_AEAD_IV_SIZE)

func Wc_ChaCha20Poly1305_Encrypt(inKey, inIv, inAAD, inPlain, outCipher, outAuthTag []byte) int {
	if len(inKey) < CHACHA20_POLY1305_AEAD_KEYSIZE {
		return -173
	}
	if len(inIv) < CHACHA20_POLY1305_AEAD_IV_SIZE {
		return -173
	}
	if len(outAuthTag) < CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE {
		return -173
	}
	if len(outCipher) < len(inPlain) {
		return -173
	}
	var sanInAAD *C.uchar
	if len(inAAD) > 0 {
		sanInAAD = (*C.uchar)(unsafe.Pointer(&inAAD[0]))
	} else {
		sanInAAD = (*C.uchar)(unsafe.Pointer(nil))
	}
	var sanInPlain *C.uchar
	if len(inPlain) > 0 {
		sanInPlain = (*C.uchar)(unsafe.Pointer(&inPlain[0]))
	} else {
		sanInPlain = (*C.uchar)(unsafe.Pointer(nil))
	}
	var sanOutCipher *C.uchar
	if len(outCipher) > 0 {
		sanOutCipher = (*C.uchar)(unsafe.Pointer(&outCipher[0]))
	} else {
		sanOutCipher = (*C.uchar)(unsafe.Pointer(nil))
	}
	return int(C.wc_ChaCha20Poly1305_Encrypt((*C.uchar)(unsafe.Pointer(&inKey[0])), (*C.uchar)(unsafe.Pointer(&inIv[0])),
		sanInAAD, C.word32(len(inAAD)), sanInPlain, C.word32(len(inPlain)),
		sanOutCipher, (*C.uchar)(unsafe.Pointer(&outAuthTag[0]))))
}

func Wc_ChaCha20Poly1305_Decrypt(inKey, inIv, inAAD, inCipher, inAuthTag, outPlain []byte) int {
	if len(inKey) < CHACHA20_POLY1305_AEAD_KEYSIZE {
		return -173
	}
	if len(inIv) < CHACHA20_POLY1305_AEAD_IV_SIZE {
		return -173
	}
	if len(inAuthTag) < CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE {
		return -173
	}
	if len(outPlain) < len(inCipher) {
		return -173
	}
	var sanInAAD *C.uchar
	if len(inAAD) > 0 {
		sanInAAD = (*C.uchar)(unsafe.Pointer(&inAAD[0]))
	} else {
		sanInAAD = (*C.uchar)(unsafe.Pointer(nil))
	}
	var sanInCipher *C.uchar
	if len(inCipher) > 0 {
		sanInCipher = (*C.uchar)(unsafe.Pointer(&inCipher[0]))
	} else {
		sanInCipher = (*C.uchar)(unsafe.Pointer(nil))
	}
	var sanOutPlain *C.uchar
	if len(outPlain) > 0 {
		sanOutPlain = (*C.uchar)(unsafe.Pointer(&outPlain[0]))
	}

	return int(C.wc_ChaCha20Poly1305_Decrypt((*C.uchar)(unsafe.Pointer(&inKey[0])), (*C.uchar)(unsafe.Pointer(&inIv[0])),
		sanInAAD, C.word32(len(inAAD)), sanInCipher, C.word32(len(inCipher)),
		(*C.uchar)(unsafe.Pointer(&inAuthTag[0])), sanOutPlain))
}

func Wc_ChaCha20Poly1305_Appended_Tag_Encrypt(inKey, inIv, inAAD, inPlain, outCipher []byte) ([]byte, int) {
	var outAuthTag [CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE]byte
	var longOutCipher []byte

	if len(outCipher) < (len(inPlain) + CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE) {
		longOutCipher = make([]byte, len(inPlain)+CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE)
	} else {
		longOutCipher = outCipher
	}

	ret := Wc_ChaCha20Poly1305_Encrypt(inKey, inIv, inAAD, inPlain, longOutCipher[:(len(longOutCipher)-CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE)], outAuthTag[:])
	copy(longOutCipher[(len(longOutCipher)-CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE):], outAuthTag[:])
	return longOutCipher, ret
}

func Wc_ChaCha20Poly1305_Appended_Tag_Decrypt(inKey, inIv, inAAD, inCipher, outPlain []byte) int {
	if len(inCipher) < CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE {
		return BAD_FUNC_ARG
	}
	var inAuthTag [CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE]byte
	copy(inAuthTag[:], inCipher[(len(inCipher)-CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE):])
	ret := Wc_ChaCha20Poly1305_Decrypt(inKey, inIv, inAAD, inCipher[:(len(inCipher)-CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE)], inAuthTag[:], outPlain)
	return ret
}

func Wc_XChaCha20Poly1305_Encrypt(outCipher, inPlain, inAAD, inIv, inKey []byte) int {
	var sanInAAD *C.uchar
	if len(inAAD) > 0 {
		sanInAAD = (*C.uchar)(unsafe.Pointer(&inAAD[0]))
	} else {
		sanInAAD = (*C.uchar)(unsafe.Pointer(nil))
	}
	var sanInPlain *C.uchar
	if len(inPlain) > 0 {
		sanInPlain = (*C.uchar)(unsafe.Pointer(&inPlain[0]))
	} else {
		sanInPlain = (*C.uchar)(unsafe.Pointer(nil))
	}
	return int(C.wc_XChaCha20Poly1305_Encrypt((*C.uchar)(unsafe.Pointer(&outCipher[0])), C.size_t(len(outCipher)),
		sanInPlain, C.size_t(len(inPlain)), sanInAAD, C.size_t(len(inAAD)),
		(*C.uchar)(unsafe.Pointer(&inIv[0])), C.size_t(len(inIv)),
		(*C.uchar)(unsafe.Pointer(&inKey[0])), C.size_t(len(inKey))))
}

func Wc_XChaCha20Poly1305_Decrypt(outPlain, inCipher, inAAD, inIv, inKey []byte) int {
	var sanInAAD *C.uchar
	if len(inAAD) > 0 {
		sanInAAD = (*C.uchar)(unsafe.Pointer(&inAAD[0]))
	} else {
		sanInAAD = (*C.uchar)(unsafe.Pointer(nil))
	}
	var sanInCipher *C.uchar
	if len(inCipher) > 0 {
		sanInCipher = (*C.uchar)(unsafe.Pointer(&inCipher[0]))
	} else {
		sanInCipher = (*C.uchar)(unsafe.Pointer(nil))
	}
	return int(C.wc_XChaCha20Poly1305_Decrypt((*C.uchar)(unsafe.Pointer(&outPlain[0])), C.size_t(len(outPlain)),
		sanInCipher, C.size_t(len(inCipher)), sanInAAD, C.size_t(len(inAAD)),
		(*C.uchar)(unsafe.Pointer(&inIv[0])), C.size_t(len(inIv)),
		(*C.uchar)(unsafe.Pointer(&inKey[0])), C.size_t(len(inKey))))
}

// ChaChaPoly_Aead is the streaming AEAD state for ChaCha20-Poly1305.
// State machine: Wc_ChaCha20Poly1305_Init → (Wc_ChaCha20Poly1305_UpdateAad)*
//
//	→ (Wc_ChaCha20Poly1305_UpdateData)* → Wc_ChaCha20Poly1305_Final.
//
// NOT thread-safe. No Free is needed; Final zeroes the struct internally.
type ChaChaPoly_Aead = C.struct_ChaChaPoly_Aead

// Wc_ChaCha20Poly1305_Init initialises aead for encryption (isEncrypt != 0)
// or decryption (isEncrypt == 0). key must be exactly
// CHACHA20_POLY1305_AEAD_KEYSIZE bytes; iv must be exactly
// CHACHA20_POLY1305_AEAD_IV_SIZE bytes. Returns 0 on success.
func Wc_ChaCha20Poly1305_Init(aead *ChaChaPoly_Aead, key, iv []byte, isEncrypt int) int {
	if len(key) < CHACHA20_POLY1305_AEAD_KEYSIZE {
		return -173
	}
	if len(iv) < CHACHA20_POLY1305_AEAD_IV_SIZE {
		return -173
	}
	return int(C.wc_ChaCha20Poly1305_Init_shim(
		aead,
		(*C.uchar)(unsafe.Pointer(&key[0])),
		(*C.uchar)(unsafe.Pointer(&iv[0])),
		C.int(isEncrypt),
	))
}

// Wc_ChaCha20Poly1305_UpdateAad feeds additional authenticated data into the
// AEAD state. Must be called after Init and before any UpdateData call.
// inAADLen must be <= len(inAAD). Returns 0 on success.
func Wc_ChaCha20Poly1305_UpdateAad(aead *ChaChaPoly_Aead, inAAD []byte, inAADLen int) int {
	if inAADLen < 0 || inAADLen > len(inAAD) {
		return -173
	}
	var sanInAAD *C.uchar
	if inAADLen > 0 {
		sanInAAD = (*C.uchar)(unsafe.Pointer(&inAAD[0]))
	} else {
		sanInAAD = (*C.uchar)(unsafe.Pointer(nil))
	}
	return int(C.wc_ChaCha20Poly1305_UpdateAad(aead, sanInAAD, C.word32(inAADLen)))
}

// Wc_ChaCha20Poly1305_UpdateData encrypts or decrypts inDataLen bytes from
// inData into outData. inData and outData may alias (in-place). outData must
// be at least inDataLen bytes. inDataLen must be <= len(inData).
// If inDataLen is 0, returns 0 immediately without advancing internal state.
// Returns 0 on success.
func Wc_ChaCha20Poly1305_UpdateData(aead *ChaChaPoly_Aead, inData []byte, inDataLen int, outData []byte) int {
	if inDataLen < 0 || inDataLen > len(inData) {
		return -173
	}
	if len(outData) < inDataLen {
		return -173
	}
	if inDataLen == 0 {
		return 0
	}
	return int(C.wc_ChaCha20Poly1305_UpdateData(
		aead,
		(*C.uchar)(unsafe.Pointer(&inData[0])),
		(*C.uchar)(unsafe.Pointer(&outData[0])),
		C.word32(inDataLen),
	))
}

// Wc_ChaCha20Poly1305_Final finalises the AEAD operation and writes the
// 16-byte authentication tag into outAuthTag, which must be at least
// CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE bytes. The struct is zeroed by wolfSSL
// on completion; do not call Free afterwards. Returns 0 on success.
func Wc_ChaCha20Poly1305_Final(aead *ChaChaPoly_Aead, outAuthTag []byte) int {
	if len(outAuthTag) < CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE {
		return -173
	}
	return int(C.wc_ChaCha20Poly1305_Final_shim(
		aead,
		(*C.uchar)(unsafe.Pointer(&outAuthTag[0])),
	))
}
