/* ed448.go
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
// #include <wolfssl/wolfcrypt/ed448.h>
// #include <wolfssl/wolfcrypt/random.h>
// #include <wolfssl/wolfcrypt/memory.h>
//
// #ifndef HAVE_ED448
// typedef struct ed448_key {} ed448_key;
// #endif
//
// /* --- Init / Free --- */
//
// static int go_wc_ed448_init(ed448_key* key) {
// #ifdef HAVE_ED448
//     return wc_ed448_init(key);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_ed448_init_ex(ed448_key* key, void* heap, int devId) {
// #ifdef HAVE_ED448
//     return wc_ed448_init_ex(key, heap, devId);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static void go_wc_ed448_free(ed448_key* key) {
// #ifdef HAVE_ED448
//     wc_ed448_free(key);
// #endif
// }
//
// /* --- Key generation --- */
//
// static int go_wc_ed448_make_key(WC_RNG* rng, int keysize, ed448_key* key) {
// #ifdef HAVE_ED448
//     return wc_ed448_make_key(rng, keysize, key);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_ed448_make_public(ed448_key* key, unsigned char* pubKey, word32 pubKeySz) {
// #ifdef HAVE_ED448
//     return wc_ed448_make_public(key, pubKey, pubKeySz);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* --- Sign --- */
//
// static int go_wc_ed448_sign_msg(const byte* in, word32 inLen, byte* out, word32* outLen,
//                                 ed448_key* key, const byte* context, byte contextLen) {
// #if defined(HAVE_ED448) && defined(HAVE_ED448_SIGN)
//     return wc_ed448_sign_msg(in, inLen, out, outLen, key, context, contextLen);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_ed448ph_sign_msg(const byte* in, word32 inLen, byte* out, word32* outLen,
//                                   ed448_key* key, const byte* context, byte contextLen) {
// #if defined(HAVE_ED448) && defined(HAVE_ED448_SIGN)
//     return wc_ed448ph_sign_msg(in, inLen, out, outLen, key, context, contextLen);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* --- Verify --- */
//
// static int go_wc_ed448_verify_msg(const byte* sig, word32 sigLen, const byte* msg,
//                                   word32 msgLen, int* res, ed448_key* key,
//                                   const byte* context, byte contextLen) {
// #if defined(HAVE_ED448) && defined(HAVE_ED448_VERIFY)
//     return wc_ed448_verify_msg(sig, sigLen, msg, msgLen, res, key, context, contextLen);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_ed448ph_verify_msg(const byte* sig, word32 sigLen, const byte* msg,
//                                     word32 msgLen, int* res, ed448_key* key,
//                                     const byte* context, byte contextLen) {
// #if defined(HAVE_ED448) && defined(HAVE_ED448_VERIFY)
//     return wc_ed448ph_verify_msg(sig, sigLen, msg, msgLen, res, key, context, contextLen);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* --- Key import --- */
//
// static int go_wc_ed448_import_public(const byte* in, word32 inLen, ed448_key* key) {
// #if defined(HAVE_ED448) && defined(HAVE_ED448_KEY_IMPORT)
//     return wc_ed448_import_public(in, inLen, key);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_ed448_import_public_ex(const byte* in, word32 inLen, ed448_key* key, int trusted) {
// #if defined(HAVE_ED448) && defined(HAVE_ED448_KEY_IMPORT)
//     return wc_ed448_import_public_ex(in, inLen, key, trusted);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_ed448_import_private_only(const byte* priv, word32 privSz, ed448_key* key) {
// #if defined(HAVE_ED448) && defined(HAVE_ED448_KEY_IMPORT)
//     return wc_ed448_import_private_only(priv, privSz, key);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_ed448_import_private_key(const byte* priv, word32 privSz,
//                                           const byte* pub, word32 pubSz, ed448_key* key) {
// #if defined(HAVE_ED448) && defined(HAVE_ED448_KEY_IMPORT)
//     return wc_ed448_import_private_key(priv, privSz, pub, pubSz, key);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_ed448_import_private_key_ex(const byte* priv, word32 privSz,
//                                              const byte* pub, word32 pubSz,
//                                              ed448_key* key, int trusted) {
// #if defined(HAVE_ED448) && defined(HAVE_ED448_KEY_IMPORT)
//     return wc_ed448_import_private_key_ex(priv, privSz, pub, pubSz, key, trusted);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* --- Key export --- */
//
// static int go_wc_ed448_export_public(const ed448_key* key, byte* out, word32* outLen) {
// #if defined(HAVE_ED448) && defined(HAVE_ED448_KEY_EXPORT)
//     return wc_ed448_export_public(key, out, outLen);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_ed448_export_private_only(const ed448_key* key, byte* out, word32* outLen) {
// #if defined(HAVE_ED448) && defined(HAVE_ED448_KEY_EXPORT)
//     return wc_ed448_export_private_only(key, out, outLen);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_ed448_export_private(const ed448_key* key, byte* out, word32* outLen) {
// #if defined(HAVE_ED448) && defined(HAVE_ED448_KEY_EXPORT)
//     return wc_ed448_export_private(key, out, outLen);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_ed448_export_key(const ed448_key* key,
//                                   byte* priv, word32* privSz,
//                                   byte* pub, word32* pubSz) {
// #if defined(HAVE_ED448) && defined(HAVE_ED448_KEY_EXPORT)
//     return wc_ed448_export_key(key, priv, privSz, pub, pubSz);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* --- Validation and size queries --- */
//
// static int go_wc_ed448_check_key(ed448_key* key) {
// #ifdef HAVE_ED448
//     return wc_ed448_check_key(key);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_ed448_size(const ed448_key* key) {
// #ifdef HAVE_ED448
//     return wc_ed448_size(key);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_ed448_priv_size(const ed448_key* key) {
// #ifdef HAVE_ED448
//     return wc_ed448_priv_size(key);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_ed448_pub_size(const ed448_key* key) {
// #ifdef HAVE_ED448
//     return wc_ed448_pub_size(key);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_ed448_sig_size(const ed448_key* key) {
// #ifdef HAVE_ED448
//     return wc_ed448_sig_size(key);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
import "C"
import "unsafe"

// Ed448Key is a type alias for the wolfSSL ed448_key struct.
// ed448_key structs are NOT thread-safe; callers must not share a key
// across goroutines without external synchronization.
type Ed448Key = C.struct_ed448_key

// Ed448 key and signature size constants.
const (
	ED448_KEY_SIZE     = int(C.ED448_KEY_SIZE)
	ED448_SIG_SIZE     = int(C.ED448_SIG_SIZE)
	ED448_PUB_KEY_SIZE = int(C.ED448_PUB_KEY_SIZE)
	ED448_PRV_KEY_SIZE = int(C.ED448_PRV_KEY_SIZE)
)

// Wc_Ed448Init initializes an ed448_key struct.
// Returns 0 on success, negative on error.
func Wc_Ed448Init(key *C.struct_ed448_key) int {
	return int(C.go_wc_ed448_init(key))
}

// Wc_Ed448InitEx initializes an ed448_key struct with a heap hint and device ID.
// Returns 0 on success, negative on error.
func Wc_Ed448InitEx(key *C.struct_ed448_key, heap unsafe.Pointer, devId int) int {
	return int(C.go_wc_ed448_init_ex(key, heap, C.int(devId)))
}

// Wc_Ed448Free releases resources associated with an ed448_key struct.
func Wc_Ed448Free(key *C.struct_ed448_key) {
	C.go_wc_ed448_free(key)
}

// Wc_Ed448MakeKey generates a new Ed448 key pair into key.
// keysize must be ED448_KEY_SIZE (57).
// Returns 0 on success, negative on error.
func Wc_Ed448MakeKey(rng *C.struct_WC_RNG, keysize int, key *C.struct_ed448_key) int {
	return int(C.go_wc_ed448_make_key(rng, C.int(keysize), key))
}

// Wc_Ed448MakePublic derives the public key from an already-loaded private key.
// pubKey must be at least ED448_PUB_KEY_SIZE bytes; pubKeySz is the buffer length.
// Returns 0 on success, negative on error.
func Wc_Ed448MakePublic(key *C.struct_ed448_key, pubKey []byte, pubKeySz int) int {
	if pubKeySz < 0 || pubKeySz > len(pubKey) {
		return BAD_FUNC_ARG
	}
	if pubKeySz < ED448_PUB_KEY_SIZE {
		return BAD_FUNC_ARG
	}
	if len(pubKey) < ED448_PUB_KEY_SIZE {
		return BAD_FUNC_ARG
	}
	return int(C.go_wc_ed448_make_public(key, (*C.uchar)(unsafe.Pointer(&pubKey[0])), C.word32(pubKeySz)))
}

// Wc_Ed448SignMsg signs the message in[0:inSz] with key, writing the signature
// into out. outSz is updated to the actual signature length on success.
// context may be nil when contextLen is 0.
// out must be at least ED448_SIG_SIZE bytes.
// Returns 0 on success, negative on error.
func Wc_Ed448SignMsg(key *C.struct_ed448_key, in []byte, inSz int, out []byte, outSz *int,
	context []byte, contextLen int) int {
	if inSz < 0 || inSz > len(in) {
		return BAD_FUNC_ARG
	}
	if contextLen < 0 || contextLen > 255 || contextLen > len(context) {
		return BAD_FUNC_ARG
	}
	if outSz == nil || len(out) < ED448_SIG_SIZE {
		return BAD_FUNC_ARG
	}
	var inPtr *C.byte
	if len(in) > 0 {
		inPtr = (*C.byte)(unsafe.Pointer(&in[0]))
	}
	cOutSz := C.word32(len(out))
	var ctxPtr *C.byte
	if contextLen > 0 {
		ctxPtr = (*C.byte)(unsafe.Pointer(&context[0]))
	}
	ret := int(C.go_wc_ed448_sign_msg(
		inPtr, C.word32(inSz),
		(*C.byte)(unsafe.Pointer(&out[0])), &cOutSz,
		key, ctxPtr, C.byte(contextLen)))
	if ret == 0 {
		*outSz = int(cOutSz)
	}
	return ret
}

// Wc_Ed448CtxSignMsg signs the message using Ed448 with a domain separation context.
// context may be nil when contextLen is 0.
// out must be at least ED448_SIG_SIZE bytes.
// Returns 0 on success, negative on error.
func Wc_Ed448CtxSignMsg(key *C.struct_ed448_key, in []byte, inSz int, out []byte, outSz *int,
	context []byte, contextLen int) int {
	return Wc_Ed448SignMsg(key, in, inSz, out, outSz, context, contextLen)
}

// Wc_Ed448PhSignMsg signs the message using Ed448ph (pre-hash variant).
// context may be nil when contextLen is 0.
// out must be at least ED448_SIG_SIZE bytes.
// Returns 0 on success, negative on error.
func Wc_Ed448PhSignMsg(key *C.struct_ed448_key, in []byte, inSz int, out []byte, outSz *int,
	context []byte, contextLen int) int {
	if inSz < 0 || inSz > len(in) {
		return BAD_FUNC_ARG
	}
	if contextLen < 0 || contextLen > 255 || contextLen > len(context) {
		return BAD_FUNC_ARG
	}
	if outSz == nil || len(out) < ED448_SIG_SIZE {
		return BAD_FUNC_ARG
	}
	var inPtr *C.byte
	if len(in) > 0 {
		inPtr = (*C.byte)(unsafe.Pointer(&in[0]))
	}
	cOutSz := C.word32(len(out))
	var ctxPtr *C.byte
	if contextLen > 0 {
		ctxPtr = (*C.byte)(unsafe.Pointer(&context[0]))
	}
	ret := int(C.go_wc_ed448ph_sign_msg(
		inPtr, C.word32(inSz),
		(*C.byte)(unsafe.Pointer(&out[0])), &cOutSz,
		key, ctxPtr, C.byte(contextLen)))
	if ret == 0 {
		*outSz = int(cOutSz)
	}
	return ret
}

// Wc_Ed448VerifyMsg verifies sig against msg using key.
// context may be nil when contextLen is 0.
// res is set to 1 on valid signature, 0 on invalid.
// Returns 0 on success (check res for validity), negative on error.
func Wc_Ed448VerifyMsg(sig []byte, sigLen int, msg []byte, msgLen int, res *int,
	key *C.struct_ed448_key, context []byte, contextLen int) int {
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
	}
	cRes := C.int(0)
	var ctxPtr *C.byte
	if contextLen > 0 {
		ctxPtr = (*C.byte)(unsafe.Pointer(&context[0]))
	}
	ret := int(C.go_wc_ed448_verify_msg(
		(*C.byte)(unsafe.Pointer(&sig[0])), C.word32(sigLen),
		msgPtr, C.word32(msgLen),
		&cRes, key, ctxPtr, C.byte(contextLen)))
	if ret == 0 {
		*res = int(cRes)
	}
	return ret
}

// Wc_Ed448CtxVerifyMsg verifies sig against msg using Ed448 with a domain separation context.
// context may be nil when contextLen is 0.
// res is set to 1 on valid signature, 0 on invalid.
// Returns 0 on success (check res for validity), negative on error.
func Wc_Ed448CtxVerifyMsg(sig []byte, sigLen int, msg []byte, msgLen int, res *int,
	key *C.struct_ed448_key, context []byte, contextLen int) int {
	return Wc_Ed448VerifyMsg(sig, sigLen, msg, msgLen, res, key, context, contextLen)
}

// Wc_Ed448PhVerifyMsg verifies sig against msg using Ed448ph (pre-hash variant).
// context may be nil when contextLen is 0.
// res is set to 1 on valid signature, 0 on invalid.
// Returns 0 on success (check res for validity), negative on error.
func Wc_Ed448PhVerifyMsg(sig []byte, sigLen int, msg []byte, msgLen int, res *int,
	key *C.struct_ed448_key, context []byte, contextLen int) int {
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
	}
	cRes := C.int(0)
	var ctxPtr *C.byte
	if contextLen > 0 {
		ctxPtr = (*C.byte)(unsafe.Pointer(&context[0]))
	}
	ret := int(C.go_wc_ed448ph_verify_msg(
		(*C.byte)(unsafe.Pointer(&sig[0])), C.word32(sigLen),
		msgPtr, C.word32(msgLen),
		&cRes, key, ctxPtr, C.byte(contextLen)))
	if ret == 0 {
		*res = int(cRes)
	}
	return ret
}

// Wc_Ed448ImportPublic imports a compressed public key (ED448_PUB_KEY_SIZE bytes) into key.
// inLen must be <= len(in).
// Returns 0 on success, negative on error.
func Wc_Ed448ImportPublic(in []byte, inLen int, key *C.struct_ed448_key) int {
	if inLen < 0 || inLen > len(in) {
		return BAD_FUNC_ARG
	}
	if len(in) == 0 {
		return BAD_FUNC_ARG
	}
	return int(C.go_wc_ed448_import_public((*C.byte)(unsafe.Pointer(&in[0])), C.word32(inLen), key))
}

// Wc_Ed448ImportPublicEx imports a compressed public key, with a trusted flag.
// trusted non-zero skips point validation.
// Returns 0 on success, negative on error.
func Wc_Ed448ImportPublicEx(in []byte, inLen int, key *C.struct_ed448_key, trusted int) int {
	if inLen < 0 || inLen > len(in) {
		return BAD_FUNC_ARG
	}
	if len(in) == 0 {
		return BAD_FUNC_ARG
	}
	return int(C.go_wc_ed448_import_public_ex((*C.byte)(unsafe.Pointer(&in[0])), C.word32(inLen), key, C.int(trusted)))
}

// Wc_Ed448ImportPrivateOnly imports only the 57-byte private seed into key.
// privSz must be <= len(priv).
// Returns 0 on success, negative on error.
func Wc_Ed448ImportPrivateOnly(priv []byte, privSz int, key *C.struct_ed448_key) int {
	if privSz < 0 || privSz > len(priv) {
		return BAD_FUNC_ARG
	}
	if len(priv) == 0 {
		return BAD_FUNC_ARG
	}
	return int(C.go_wc_ed448_import_private_only((*C.byte)(unsafe.Pointer(&priv[0])), C.word32(privSz), key))
}

// Wc_Ed448ImportPrivateKey imports a private seed and the corresponding public key into key.
// privSz must be <= len(priv); pubSz must be <= len(pub).
// Returns 0 on success, negative on error.
func Wc_Ed448ImportPrivateKey(priv []byte, privSz int, pub []byte, pubSz int, key *C.struct_ed448_key) int {
	if privSz < 0 || privSz > len(priv) {
		return BAD_FUNC_ARG
	}
	if pubSz < 0 || pubSz > len(pub) {
		return BAD_FUNC_ARG
	}
	if len(priv) == 0 || len(pub) == 0 {
		return BAD_FUNC_ARG
	}
	return int(C.go_wc_ed448_import_private_key(
		(*C.byte)(unsafe.Pointer(&priv[0])), C.word32(privSz),
		(*C.byte)(unsafe.Pointer(&pub[0])), C.word32(pubSz),
		key))
}

// Wc_Ed448ImportPrivateKeyEx imports a private seed and public key into key, with a trusted flag.
// trusted non-zero skips point validation on the public key.
// Returns 0 on success, negative on error.
func Wc_Ed448ImportPrivateKeyEx(priv []byte, privSz int, pub []byte, pubSz int, key *C.struct_ed448_key, trusted int) int {
	if privSz < 0 || privSz > len(priv) {
		return BAD_FUNC_ARG
	}
	if pubSz < 0 || pubSz > len(pub) {
		return BAD_FUNC_ARG
	}
	if len(priv) == 0 || len(pub) == 0 {
		return BAD_FUNC_ARG
	}
	return int(C.go_wc_ed448_import_private_key_ex(
		(*C.byte)(unsafe.Pointer(&priv[0])), C.word32(privSz),
		(*C.byte)(unsafe.Pointer(&pub[0])), C.word32(pubSz),
		key, C.int(trusted)))
}

// Wc_Ed448ExportPublic exports the public key from key into out.
// outLen is updated to the actual number of bytes written on success.
// out must be at least ED448_PUB_KEY_SIZE bytes.
// Returns 0 on success, negative on error.
func Wc_Ed448ExportPublic(key *C.struct_ed448_key, out []byte, outLen *int) int {
	if outLen == nil || len(out) < ED448_PUB_KEY_SIZE {
		return BAD_FUNC_ARG
	}
	cOutLen := C.word32(len(out))
	ret := int(C.go_wc_ed448_export_public(key, (*C.byte)(unsafe.Pointer(&out[0])), &cOutLen))
	if ret == 0 {
		*outLen = int(cOutLen)
	}
	return ret
}

// Wc_Ed448ExportPrivateOnly exports only the 57-byte private seed from key into out.
// outLen is updated to the actual number of bytes written on success.
// out must be at least ED448_KEY_SIZE bytes.
// Returns 0 on success, negative on error.
func Wc_Ed448ExportPrivateOnly(key *C.struct_ed448_key, out []byte, outLen *int) int {
	if outLen == nil || len(out) < ED448_KEY_SIZE {
		return BAD_FUNC_ARG
	}
	cOutLen := C.word32(len(out))
	ret := int(C.go_wc_ed448_export_private_only(key, (*C.byte)(unsafe.Pointer(&out[0])), &cOutLen))
	if ret == 0 {
		*outLen = int(cOutLen)
	}
	return ret
}

// Wc_Ed448ExportPrivate exports the full private key (seed || public) from key into out.
// outLen is updated to the actual number of bytes written on success.
// out must be at least ED448_PRV_KEY_SIZE bytes.
// Returns 0 on success, negative on error.
func Wc_Ed448ExportPrivate(key *C.struct_ed448_key, out []byte, outLen *int) int {
	if outLen == nil || len(out) < ED448_PRV_KEY_SIZE {
		return BAD_FUNC_ARG
	}
	cOutLen := C.word32(len(out))
	ret := int(C.go_wc_ed448_export_private(key, (*C.byte)(unsafe.Pointer(&out[0])), &cOutLen))
	if ret == 0 {
		*outLen = int(cOutLen)
	}
	return ret
}

// Wc_Ed448ExportKey exports both the private (seed || public) and public key from key.
// privSz and pubSz are updated to the actual byte counts on success.
// priv must be at least ED448_PRV_KEY_SIZE bytes; pub must be at least ED448_PUB_KEY_SIZE bytes.
// Returns 0 on success, negative on error.
func Wc_Ed448ExportKey(key *C.struct_ed448_key, priv []byte, privSz *int, pub []byte, pubSz *int) int {
	if privSz == nil || len(priv) < ED448_PRV_KEY_SIZE {
		return BAD_FUNC_ARG
	}
	if pubSz == nil || len(pub) < ED448_PUB_KEY_SIZE {
		return BAD_FUNC_ARG
	}
	cPrivSz := C.word32(len(priv))
	cPubSz := C.word32(len(pub))
	ret := int(C.go_wc_ed448_export_key(key,
		(*C.byte)(unsafe.Pointer(&priv[0])), &cPrivSz,
		(*C.byte)(unsafe.Pointer(&pub[0])), &cPubSz))
	if ret == 0 {
		*privSz = int(cPrivSz)
		*pubSz = int(cPubSz)
	}
	return ret
}

// Wc_Ed448CheckKey validates the internal consistency of key.
// Returns 0 on success, negative on error.
func Wc_Ed448CheckKey(key *C.struct_ed448_key) int {
	return int(C.go_wc_ed448_check_key(key))
}

// Wc_Ed448Size returns the private key size for key (ED448_KEY_SIZE = 57).
// Returns the size in bytes, or negative on error.
func Wc_Ed448Size(key *C.struct_ed448_key) int {
	return int(C.go_wc_ed448_size(key))
}

// Wc_Ed448PrivSize returns the full private key size for key (ED448_PRV_KEY_SIZE = 114).
// Returns the size in bytes, or negative on error.
func Wc_Ed448PrivSize(key *C.struct_ed448_key) int {
	return int(C.go_wc_ed448_priv_size(key))
}

// Wc_Ed448PubSize returns the public key size for key (ED448_PUB_KEY_SIZE = 57).
// Returns the size in bytes, or negative on error.
func Wc_Ed448PubSize(key *C.struct_ed448_key) int {
	return int(C.go_wc_ed448_pub_size(key))
}

// Wc_Ed448SigSize returns the signature size for key (ED448_SIG_SIZE = 114).
// Returns the size in bytes, or negative on error.
func Wc_Ed448SigSize(key *C.struct_ed448_key) int {
	return int(C.go_wc_ed448_sig_size(key))
}
