/* ed25519.go
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
// #include <wolfssl/wolfcrypt/ed25519.h>
// #include <wolfssl/wolfcrypt/random.h>
// #include <wolfssl/wolfcrypt/memory.h>
//
// #ifndef HAVE_ED25519
// typedef struct ed25519_key {} ed25519_key;
// #endif
//
// /* --- Init / Free --- */
//
// static int go_wc_ed25519_init(ed25519_key* key) {
// #ifdef HAVE_ED25519
//     return wc_ed25519_init(key);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_ed25519_init_ex(ed25519_key* key, void* heap, int devId) {
// #ifdef HAVE_ED25519
//     return wc_ed25519_init_ex(key, heap, devId);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static void go_wc_ed25519_free(ed25519_key* key) {
// #ifdef HAVE_ED25519
//     wc_ed25519_free(key);
// #endif
// }
//
// /* --- Key generation --- */
//
// static int go_wc_ed25519_make_key(WC_RNG* rng, int keysize, ed25519_key* key) {
// #ifdef HAVE_ED25519
//     return wc_ed25519_make_key(rng, keysize, key);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_ed25519_make_public(ed25519_key* key, unsigned char* pubKey, word32 pubKeySz) {
// #ifdef HAVE_ED25519
//     return wc_ed25519_make_public(key, pubKey, pubKeySz);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* --- Sign --- */
//
// static int go_wc_ed25519_sign_msg(const byte* in, word32 inLen, byte* out, word32* outLen, ed25519_key* key) {
// #if defined(HAVE_ED25519) && defined(HAVE_ED25519_SIGN)
//     return wc_ed25519_sign_msg(in, inLen, out, outLen, key);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_ed25519ctx_sign_msg(const byte* in, word32 inLen, byte* out, word32* outLen,
//                                      ed25519_key* key, const byte* context, byte contextLen) {
// #if defined(HAVE_ED25519) && defined(HAVE_ED25519_SIGN)
//     return wc_ed25519ctx_sign_msg(in, inLen, out, outLen, key, context, contextLen);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_ed25519ph_sign_msg(const byte* in, word32 inLen, byte* out, word32* outLen,
//                                     ed25519_key* key, const byte* context, byte contextLen) {
// #if defined(HAVE_ED25519) && defined(HAVE_ED25519_SIGN)
//     return wc_ed25519ph_sign_msg(in, inLen, out, outLen, key, context, contextLen);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* --- Verify --- */
//
// static int go_wc_ed25519_verify_msg(const byte* sig, word32 sigLen, const byte* msg,
//                                     word32 msgLen, int* res, ed25519_key* key) {
// #if defined(HAVE_ED25519) && defined(HAVE_ED25519_VERIFY)
//     return wc_ed25519_verify_msg(sig, sigLen, msg, msgLen, res, key);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_ed25519ctx_verify_msg(const byte* sig, word32 sigLen, const byte* msg,
//                                        word32 msgLen, int* res, ed25519_key* key,
//                                        const byte* context, byte contextLen) {
// #if defined(HAVE_ED25519) && defined(HAVE_ED25519_VERIFY)
//     return wc_ed25519ctx_verify_msg(sig, sigLen, msg, msgLen, res, key, context, contextLen);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_ed25519ph_verify_msg(const byte* sig, word32 sigLen, const byte* msg,
//                                       word32 msgLen, int* res, ed25519_key* key,
//                                       const byte* context, byte contextLen) {
// #if defined(HAVE_ED25519) && defined(HAVE_ED25519_VERIFY)
//     return wc_ed25519ph_verify_msg(sig, sigLen, msg, msgLen, res, key, context, contextLen);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* --- Key import --- */
//
// static int go_wc_ed25519_import_public(const byte* in, word32 inLen, ed25519_key* key) {
// #if defined(HAVE_ED25519) && defined(HAVE_ED25519_KEY_IMPORT)
//     return wc_ed25519_import_public(in, inLen, key);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_ed25519_import_public_ex(const byte* in, word32 inLen, ed25519_key* key, int trusted) {
// #if defined(HAVE_ED25519) && defined(HAVE_ED25519_KEY_IMPORT)
//     return wc_ed25519_import_public_ex(in, inLen, key, trusted);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_ed25519_import_private_only(const byte* priv, word32 privSz, ed25519_key* key) {
// #if defined(HAVE_ED25519) && defined(HAVE_ED25519_KEY_IMPORT)
//     return wc_ed25519_import_private_only(priv, privSz, key);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_ed25519_import_private_key(const byte* priv, word32 privSz,
//                                             const byte* pub, word32 pubSz, ed25519_key* key) {
// #if defined(HAVE_ED25519) && defined(HAVE_ED25519_KEY_IMPORT)
//     return wc_ed25519_import_private_key(priv, privSz, pub, pubSz, key);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_ed25519_import_private_key_ex(const byte* priv, word32 privSz,
//                                                const byte* pub, word32 pubSz,
//                                                ed25519_key* key, int trusted) {
// #if defined(HAVE_ED25519) && defined(HAVE_ED25519_KEY_IMPORT)
//     return wc_ed25519_import_private_key_ex(priv, privSz, pub, pubSz, key, trusted);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* --- Key export --- */
//
// static int go_wc_ed25519_export_public(const ed25519_key* key, byte* out, word32* outLen) {
// #if defined(HAVE_ED25519) && defined(HAVE_ED25519_KEY_EXPORT)
//     return wc_ed25519_export_public(key, out, outLen);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_ed25519_export_private_only(const ed25519_key* key, byte* out, word32* outLen) {
// #if defined(HAVE_ED25519) && defined(HAVE_ED25519_KEY_EXPORT)
//     return wc_ed25519_export_private_only(key, out, outLen);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_ed25519_export_private(const ed25519_key* key, byte* out, word32* outLen) {
// #if defined(HAVE_ED25519) && defined(HAVE_ED25519_KEY_EXPORT)
//     return wc_ed25519_export_private(key, out, outLen);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_ed25519_export_key(const ed25519_key* key,
//                                     byte* priv, word32* privSz,
//                                     byte* pub, word32* pubSz) {
// #if defined(HAVE_ED25519) && defined(HAVE_ED25519_KEY_EXPORT)
//     return wc_ed25519_export_key(key, priv, privSz, pub, pubSz);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* --- Validation and size queries --- */
//
// static int go_wc_ed25519_check_key(ed25519_key* key) {
// #ifdef HAVE_ED25519
//     return wc_ed25519_check_key(key);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_ed25519_size(const ed25519_key* key) {
// #ifdef HAVE_ED25519
//     return wc_ed25519_size(key);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_ed25519_priv_size(const ed25519_key* key) {
// #ifdef HAVE_ED25519
//     return wc_ed25519_priv_size(key);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_ed25519_pub_size(const ed25519_key* key) {
// #ifdef HAVE_ED25519
//     return wc_ed25519_pub_size(key);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_ed25519_sig_size(const ed25519_key* key) {
// #ifdef HAVE_ED25519
//     return wc_ed25519_sig_size(key);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
import "C"
import "unsafe"

// Ed25519Key is a type alias for the wolfSSL ed25519_key struct.
// ed25519_key structs are NOT thread-safe; callers must not share a key
// across goroutines without external synchronization.
type Ed25519Key = C.struct_ed25519_key

// Ed25519 key and signature size constants.
const (
	ED25519_KEY_SIZE     = int(C.ED25519_KEY_SIZE)
	ED25519_SIG_SIZE     = int(C.ED25519_SIG_SIZE)
	ED25519_PUB_KEY_SIZE = int(C.ED25519_PUB_KEY_SIZE)
	ED25519_PRV_KEY_SIZE = int(C.ED25519_PRV_KEY_SIZE)
)

// ed25519EmptyMsg is a non-nil backing for zero-length message slices.
// wolfSSL rejects NULL in/msg pointers even when inLen == 0.
var ed25519EmptyMsg [1]byte

// Wc_Ed25519Init initializes an ed25519_key struct.
// Returns 0 on success, negative on error.
func Wc_Ed25519Init(key *C.struct_ed25519_key) int {
	return int(C.go_wc_ed25519_init(key))
}

// Wc_Ed25519InitEx initializes an ed25519_key struct with a heap hint and device ID.
// Returns 0 on success, negative on error.
func Wc_Ed25519InitEx(key *C.struct_ed25519_key, heap unsafe.Pointer, devId int) int {
	return int(C.go_wc_ed25519_init_ex(key, heap, C.int(devId)))
}

// Wc_Ed25519Free releases resources associated with an ed25519_key struct.
func Wc_Ed25519Free(key *C.struct_ed25519_key) {
	C.go_wc_ed25519_free(key)
}

// Wc_Ed25519MakeKey generates a new Ed25519 key pair into key.
// keysize must be ED25519_KEY_SIZE (32).
// Returns 0 on success, negative on error.
func Wc_Ed25519MakeKey(rng *C.struct_WC_RNG, keysize int, key *C.struct_ed25519_key) int {
	return int(C.go_wc_ed25519_make_key(rng, C.int(keysize), key))
}

// Wc_Ed25519MakePublic derives the public key from an already-loaded private key.
// pubKey must be at least ED25519_PUB_KEY_SIZE bytes; pubKeySz is the buffer length.
// Returns 0 on success, negative on error.
func Wc_Ed25519MakePublic(key *C.struct_ed25519_key, pubKey []byte, pubKeySz int) int {
	if pubKeySz < 0 || pubKeySz > len(pubKey) {
		return BAD_FUNC_ARG
	}
	if pubKeySz < ED25519_PUB_KEY_SIZE {
		return BAD_FUNC_ARG
	}
	if len(pubKey) < ED25519_PUB_KEY_SIZE {
		return BAD_FUNC_ARG
	}
	return int(C.go_wc_ed25519_make_public(key, (*C.uchar)(unsafe.Pointer(&pubKey[0])), C.word32(pubKeySz)))
}

// Wc_Ed25519SignMsg signs the message in[0:inSz] with key, writing the signature
// into out. outSz is updated to the actual signature length on success.
// out must be at least ED25519_SIG_SIZE bytes.
// Returns 0 on success, negative on error.
func Wc_Ed25519SignMsg(key *C.struct_ed25519_key, in []byte, inSz int, out []byte, outSz *int) int {
	if inSz < 0 || inSz > len(in) {
		return BAD_FUNC_ARG
	}
	if outSz == nil || len(out) < ED25519_SIG_SIZE {
		return BAD_FUNC_ARG
	}
	var inPtr *C.byte
	if len(in) > 0 {
		inPtr = (*C.byte)(unsafe.Pointer(&in[0]))
	} else {
		inPtr = (*C.byte)(unsafe.Pointer(&ed25519EmptyMsg[0]))
	}
	cOutSz := C.word32(len(out))
	ret := int(C.go_wc_ed25519_sign_msg(
		inPtr, C.word32(inSz),
		(*C.byte)(unsafe.Pointer(&out[0])), &cOutSz,
		key))
	if ret == 0 {
		*outSz = int(cOutSz)
	}
	return ret
}

// Wc_Ed25519CtxSignMsg signs the message using Ed25519ctx (with domain separation context).
// context may be nil when contextLen is 0.
// out must be at least ED25519_SIG_SIZE bytes.
// Returns 0 on success, negative on error.
func Wc_Ed25519CtxSignMsg(key *C.struct_ed25519_key, in []byte, inSz int, out []byte, outSz *int,
	context []byte, contextLen int) int {
	if inSz < 0 || inSz > len(in) {
		return BAD_FUNC_ARG
	}
	if contextLen < 0 || contextLen > 255 || contextLen > len(context) {
		return BAD_FUNC_ARG
	}
	if outSz == nil || len(out) < ED25519_SIG_SIZE {
		return BAD_FUNC_ARG
	}
	var inPtr *C.byte
	if len(in) > 0 {
		inPtr = (*C.byte)(unsafe.Pointer(&in[0]))
	} else {
		inPtr = (*C.byte)(unsafe.Pointer(&ed25519EmptyMsg[0]))
	}
	cOutSz := C.word32(len(out))
	var ctxPtr *C.byte
	if contextLen > 0 {
		ctxPtr = (*C.byte)(unsafe.Pointer(&context[0]))
	}
	ret := int(C.go_wc_ed25519ctx_sign_msg(
		inPtr, C.word32(inSz),
		(*C.byte)(unsafe.Pointer(&out[0])), &cOutSz,
		key, ctxPtr, C.byte(contextLen)))
	if ret == 0 {
		*outSz = int(cOutSz)
	}
	return ret
}

// Wc_Ed25519PhSignMsg signs the message using Ed25519ph (pre-hash variant).
// context may be nil when contextLen is 0.
// out must be at least ED25519_SIG_SIZE bytes.
// Returns 0 on success, negative on error.
func Wc_Ed25519PhSignMsg(key *C.struct_ed25519_key, in []byte, inSz int, out []byte, outSz *int,
	context []byte, contextLen int) int {
	if inSz < 0 || inSz > len(in) {
		return BAD_FUNC_ARG
	}
	if contextLen < 0 || contextLen > 255 || contextLen > len(context) {
		return BAD_FUNC_ARG
	}
	if outSz == nil || len(out) < ED25519_SIG_SIZE {
		return BAD_FUNC_ARG
	}
	var inPtr *C.byte
	if len(in) > 0 {
		inPtr = (*C.byte)(unsafe.Pointer(&in[0]))
	} else {
		inPtr = (*C.byte)(unsafe.Pointer(&ed25519EmptyMsg[0]))
	}
	cOutSz := C.word32(len(out))
	var ctxPtr *C.byte
	if contextLen > 0 {
		ctxPtr = (*C.byte)(unsafe.Pointer(&context[0]))
	}
	ret := int(C.go_wc_ed25519ph_sign_msg(
		inPtr, C.word32(inSz),
		(*C.byte)(unsafe.Pointer(&out[0])), &cOutSz,
		key, ctxPtr, C.byte(contextLen)))
	if ret == 0 {
		*outSz = int(cOutSz)
	}
	return ret
}

// Wc_Ed25519VerifyMsg verifies sig against msg using key.
// res is set to 1 on valid signature, 0 on invalid.
// Returns 0 on success (check res for validity), negative on error.
func Wc_Ed25519VerifyMsg(sig []byte, sigLen int, msg []byte, msgLen int, res *int, key *C.struct_ed25519_key) int {
	if sigLen < 0 || sigLen > len(sig) {
		return BAD_FUNC_ARG
	}
	if msgLen < 0 || msgLen > len(msg) {
		return BAD_FUNC_ARG
	}
	if res == nil || len(sig) == 0 {
		return BAD_FUNC_ARG
	}
	var msgPtr *C.byte
	if len(msg) > 0 {
		msgPtr = (*C.byte)(unsafe.Pointer(&msg[0]))
	} else {
		msgPtr = (*C.byte)(unsafe.Pointer(&ed25519EmptyMsg[0]))
	}
	cRes := C.int(0)
	ret := int(C.go_wc_ed25519_verify_msg(
		(*C.byte)(unsafe.Pointer(&sig[0])), C.word32(sigLen),
		msgPtr, C.word32(msgLen),
		&cRes, key))
	if ret == 0 {
		*res = int(cRes)
	}
	return ret
}

// Wc_Ed25519CtxVerifyMsg verifies sig against msg using Ed25519ctx (with domain separation context).
// context may be nil when contextLen is 0.
// res is set to 1 on valid signature, 0 on invalid.
// Returns 0 on success (check res for validity), negative on error.
func Wc_Ed25519CtxVerifyMsg(sig []byte, sigLen int, msg []byte, msgLen int, res *int,
	key *C.struct_ed25519_key, context []byte, contextLen int) int {
	if sigLen < 0 || sigLen > len(sig) {
		return BAD_FUNC_ARG
	}
	if msgLen < 0 || msgLen > len(msg) {
		return BAD_FUNC_ARG
	}
	if contextLen < 0 || contextLen > 255 || contextLen > len(context) {
		return BAD_FUNC_ARG
	}
	if res == nil || len(sig) == 0 {
		return BAD_FUNC_ARG
	}
	var msgPtr *C.byte
	if len(msg) > 0 {
		msgPtr = (*C.byte)(unsafe.Pointer(&msg[0]))
	} else {
		msgPtr = (*C.byte)(unsafe.Pointer(&ed25519EmptyMsg[0]))
	}
	cRes := C.int(0)
	var ctxPtr *C.byte
	if contextLen > 0 {
		ctxPtr = (*C.byte)(unsafe.Pointer(&context[0]))
	}
	ret := int(C.go_wc_ed25519ctx_verify_msg(
		(*C.byte)(unsafe.Pointer(&sig[0])), C.word32(sigLen),
		msgPtr, C.word32(msgLen),
		&cRes, key, ctxPtr, C.byte(contextLen)))
	if ret == 0 {
		*res = int(cRes)
	}
	return ret
}

// Wc_Ed25519PhVerifyMsg verifies sig against msg using Ed25519ph (pre-hash variant).
// context may be nil when contextLen is 0.
// res is set to 1 on valid signature, 0 on invalid.
// Returns 0 on success (check res for validity), negative on error.
func Wc_Ed25519PhVerifyMsg(sig []byte, sigLen int, msg []byte, msgLen int, res *int,
	key *C.struct_ed25519_key, context []byte, contextLen int) int {
	if sigLen < 0 || sigLen > len(sig) {
		return BAD_FUNC_ARG
	}
	if msgLen < 0 || msgLen > len(msg) {
		return BAD_FUNC_ARG
	}
	if contextLen < 0 || contextLen > 255 || contextLen > len(context) {
		return BAD_FUNC_ARG
	}
	if res == nil || len(sig) == 0 {
		return BAD_FUNC_ARG
	}
	var msgPtr *C.byte
	if len(msg) > 0 {
		msgPtr = (*C.byte)(unsafe.Pointer(&msg[0]))
	} else {
		msgPtr = (*C.byte)(unsafe.Pointer(&ed25519EmptyMsg[0]))
	}
	cRes := C.int(0)
	var ctxPtr *C.byte
	if contextLen > 0 {
		ctxPtr = (*C.byte)(unsafe.Pointer(&context[0]))
	}
	ret := int(C.go_wc_ed25519ph_verify_msg(
		(*C.byte)(unsafe.Pointer(&sig[0])), C.word32(sigLen),
		msgPtr, C.word32(msgLen),
		&cRes, key, ctxPtr, C.byte(contextLen)))
	if ret == 0 {
		*res = int(cRes)
	}
	return ret
}

// Wc_Ed25519ImportPublic imports a compressed public key (ED25519_PUB_KEY_SIZE bytes) into key.
// inLen must be <= len(in).
// Returns 0 on success, negative on error.
func Wc_Ed25519ImportPublic(in []byte, inLen int, key *C.struct_ed25519_key) int {
	if inLen < 0 || inLen > len(in) {
		return BAD_FUNC_ARG
	}
	if len(in) == 0 {
		return BAD_FUNC_ARG
	}
	return int(C.go_wc_ed25519_import_public((*C.byte)(unsafe.Pointer(&in[0])), C.word32(inLen), key))
}

// Wc_Ed25519ImportPublicEx imports a compressed public key, with a trusted flag.
// trusted non-zero skips point validation.
// Returns 0 on success, negative on error.
func Wc_Ed25519ImportPublicEx(in []byte, inLen int, key *C.struct_ed25519_key, trusted int) int {
	if inLen < 0 || inLen > len(in) {
		return BAD_FUNC_ARG
	}
	if len(in) == 0 {
		return BAD_FUNC_ARG
	}
	return int(C.go_wc_ed25519_import_public_ex((*C.byte)(unsafe.Pointer(&in[0])), C.word32(inLen), key, C.int(trusted)))
}

// Wc_Ed25519ImportPrivateOnly imports only the 32-byte private seed into key.
// privSz must be <= len(priv).
// Returns 0 on success, negative on error.
func Wc_Ed25519ImportPrivateOnly(priv []byte, privSz int, key *C.struct_ed25519_key) int {
	if privSz < 0 || privSz > len(priv) {
		return BAD_FUNC_ARG
	}
	if len(priv) == 0 {
		return BAD_FUNC_ARG
	}
	return int(C.go_wc_ed25519_import_private_only((*C.byte)(unsafe.Pointer(&priv[0])), C.word32(privSz), key))
}

// Wc_Ed25519ImportPrivateKey imports a private seed and the corresponding public key into key.
// privSz must be <= len(priv); pubSz must be <= len(pub).
// Returns 0 on success, negative on error.
func Wc_Ed25519ImportPrivateKey(priv []byte, privSz int, pub []byte, pubSz int, key *C.struct_ed25519_key) int {
	if privSz < 0 || privSz > len(priv) {
		return BAD_FUNC_ARG
	}
	if pubSz < 0 || pubSz > len(pub) {
		return BAD_FUNC_ARG
	}
	if len(priv) == 0 || len(pub) == 0 {
		return BAD_FUNC_ARG
	}
	return int(C.go_wc_ed25519_import_private_key(
		(*C.byte)(unsafe.Pointer(&priv[0])), C.word32(privSz),
		(*C.byte)(unsafe.Pointer(&pub[0])), C.word32(pubSz),
		key))
}

// Wc_Ed25519ImportPrivateKeyEx imports a private seed and public key into key, with a trusted flag.
// trusted non-zero skips point validation on the public key.
// Returns 0 on success, negative on error.
func Wc_Ed25519ImportPrivateKeyEx(priv []byte, privSz int, pub []byte, pubSz int, key *C.struct_ed25519_key, trusted int) int {
	if privSz < 0 || privSz > len(priv) {
		return BAD_FUNC_ARG
	}
	if pubSz < 0 || pubSz > len(pub) {
		return BAD_FUNC_ARG
	}
	if len(priv) == 0 || len(pub) == 0 {
		return BAD_FUNC_ARG
	}
	return int(C.go_wc_ed25519_import_private_key_ex(
		(*C.byte)(unsafe.Pointer(&priv[0])), C.word32(privSz),
		(*C.byte)(unsafe.Pointer(&pub[0])), C.word32(pubSz),
		key, C.int(trusted)))
}

// Wc_Ed25519ExportPublic exports the public key from key into out.
// outLen is updated to the actual number of bytes written on success.
// out must be at least ED25519_PUB_KEY_SIZE bytes.
// Returns 0 on success, negative on error.
func Wc_Ed25519ExportPublic(key *C.struct_ed25519_key, out []byte, outLen *int) int {
	if outLen == nil || len(out) < ED25519_PUB_KEY_SIZE {
		return BAD_FUNC_ARG
	}
	cOutLen := C.word32(len(out))
	ret := int(C.go_wc_ed25519_export_public(key, (*C.byte)(unsafe.Pointer(&out[0])), &cOutLen))
	if ret == 0 {
		*outLen = int(cOutLen)
	}
	return ret
}

// Wc_Ed25519ExportPrivateOnly exports only the 32-byte private seed from key into out.
// outLen is updated to the actual number of bytes written on success.
// out must be at least ED25519_KEY_SIZE bytes.
// Returns 0 on success, negative on error.
func Wc_Ed25519ExportPrivateOnly(key *C.struct_ed25519_key, out []byte, outLen *int) int {
	if outLen == nil || len(out) < ED25519_KEY_SIZE {
		return BAD_FUNC_ARG
	}
	cOutLen := C.word32(len(out))
	ret := int(C.go_wc_ed25519_export_private_only(key, (*C.byte)(unsafe.Pointer(&out[0])), &cOutLen))
	if ret == 0 {
		*outLen = int(cOutLen)
	}
	return ret
}

// Wc_Ed25519ExportPrivate exports the 64-byte private key (seed || public) from key into out.
// outLen is updated to the actual number of bytes written on success.
// out must be at least ED25519_PRV_KEY_SIZE bytes.
// Returns 0 on success, negative on error.
func Wc_Ed25519ExportPrivate(key *C.struct_ed25519_key, out []byte, outLen *int) int {
	if outLen == nil || len(out) < ED25519_PRV_KEY_SIZE {
		return BAD_FUNC_ARG
	}
	cOutLen := C.word32(len(out))
	ret := int(C.go_wc_ed25519_export_private(key, (*C.byte)(unsafe.Pointer(&out[0])), &cOutLen))
	if ret == 0 {
		*outLen = int(cOutLen)
	}
	return ret
}

// Wc_Ed25519ExportKey exports both the private (seed || public) and public key from key.
// privSz and pubSz are updated to the actual byte counts on success.
// priv must be at least ED25519_PRV_KEY_SIZE bytes; pub must be at least ED25519_PUB_KEY_SIZE bytes.
// Returns 0 on success, negative on error.
func Wc_Ed25519ExportKey(key *C.struct_ed25519_key, priv []byte, privSz *int, pub []byte, pubSz *int) int {
	if privSz == nil || len(priv) < ED25519_PRV_KEY_SIZE {
		return BAD_FUNC_ARG
	}
	if pubSz == nil || len(pub) < ED25519_PUB_KEY_SIZE {
		return BAD_FUNC_ARG
	}
	cPrivSz := C.word32(len(priv))
	cPubSz := C.word32(len(pub))
	ret := int(C.go_wc_ed25519_export_key(key,
		(*C.byte)(unsafe.Pointer(&priv[0])), &cPrivSz,
		(*C.byte)(unsafe.Pointer(&pub[0])), &cPubSz))
	if ret == 0 {
		*privSz = int(cPrivSz)
		*pubSz = int(cPubSz)
	}
	return ret
}

// Wc_Ed25519CheckKey validates the internal consistency of key.
// Returns 0 on success, negative on error.
func Wc_Ed25519CheckKey(key *C.struct_ed25519_key) int {
	return int(C.go_wc_ed25519_check_key(key))
}

// Wc_Ed25519Size returns the private key size for key (ED25519_KEY_SIZE = 32).
// Returns the size in bytes, or negative on error.
func Wc_Ed25519Size(key *C.struct_ed25519_key) int {
	return int(C.go_wc_ed25519_size(key))
}

// Wc_Ed25519PrivSize returns the full private key size for key (ED25519_PRV_KEY_SIZE = 64).
// Returns the size in bytes, or negative on error.
func Wc_Ed25519PrivSize(key *C.struct_ed25519_key) int {
	return int(C.go_wc_ed25519_priv_size(key))
}

// Wc_Ed25519PubSize returns the public key size for key (ED25519_PUB_KEY_SIZE = 32).
// Returns the size in bytes, or negative on error.
func Wc_Ed25519PubSize(key *C.struct_ed25519_key) int {
	return int(C.go_wc_ed25519_pub_size(key))
}

// Wc_Ed25519SigSize returns the signature size for key (ED25519_SIG_SIZE = 64).
// Returns the size in bytes, or negative on error.
func Wc_Ed25519SigSize(key *C.struct_ed25519_key) int {
	return int(C.go_wc_ed25519_sig_size(key))
}
