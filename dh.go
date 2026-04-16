/* dh.go
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
// #include <wolfssl/wolfcrypt/dh.h>
// #include <wolfssl/wolfcrypt/random.h>
//
// /* Provide a stub struct when DH is compiled out so the Go type alias compiles. */
// #ifdef NO_DH
// typedef struct DhKey {} DhKey;
// #endif
//
// /* ---- Init / Free ------------------------------------------------------- */
//
// static int go_wc_InitDhKey(DhKey* key) {
// #ifndef NO_DH
//     return wc_InitDhKey(key);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_InitDhKey_ex(DhKey* key, void* heap, int devId) {
// #ifndef NO_DH
//     return wc_InitDhKey_ex(key, heap, devId);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_FreeDhKey(DhKey* key) {
// #ifndef NO_DH
//     return wc_FreeDhKey(key);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* ---- Set parameters ---------------------------------------------------- */
//
// static int go_wc_DhSetKey(DhKey* key,
//         const byte* p, word32 pSz,
//         const byte* g, word32 gSz) {
// #ifndef NO_DH
//     return wc_DhSetKey(key, p, pSz, g, gSz);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_DhSetKey_ex(DhKey* key,
//         const byte* p, word32 pSz,
//         const byte* g, word32 gSz,
//         const byte* q, word32 qSz) {
// #ifndef NO_DH
//     return wc_DhSetKey_ex(key, p, pSz, g, gSz, q, qSz);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* ---- Key generation ---------------------------------------------------- */
//
// static int go_wc_DhGenerateKeyPair(DhKey* key, WC_RNG* rng,
//         byte* priv, word32* privSz,
//         byte* pub, word32* pubSz) {
// #ifndef NO_DH
//     return wc_DhGenerateKeyPair(key, rng, priv, privSz, pub, pubSz);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* ---- Key agreement ----------------------------------------------------- */
//
// static int go_wc_DhAgree(DhKey* key,
//         byte* agree, word32* agreeSz,
//         const byte* priv, word32 privSz,
//         const byte* otherPub, word32 pubSz) {
// #ifndef NO_DH
//     return wc_DhAgree(key, agree, agreeSz, priv, privSz, otherPub, pubSz);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* ---- Public key checks ------------------------------------------------- */
//
// static int go_wc_DhCheckPubKey(DhKey* key, const byte* pub, word32 pubSz) {
// #ifndef NO_DH
//     return wc_DhCheckPubKey(key, pub, pubSz);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_DhCheckPubKey_ex(DhKey* key,
//         const byte* pub, word32 pubSz,
//         const byte* prime, word32 primeSz) {
// #ifndef NO_DH
//     return wc_DhCheckPubKey_ex(key, pub, pubSz, prime, primeSz);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* ---- Private key checks ------------------------------------------------ */
//
// static int go_wc_DhCheckPrivKey(DhKey* key, const byte* priv, word32 privSz) {
// #ifndef NO_DH
//     return wc_DhCheckPrivKey(key, priv, privSz);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// static int go_wc_DhCheckPrivKey_ex(DhKey* key,
//         const byte* priv, word32 privSz,
//         const byte* prime, word32 primeSz) {
// #ifndef NO_DH
//     return wc_DhCheckPrivKey_ex(key, priv, privSz, prime, primeSz);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* ---- Key pair check ---------------------------------------------------- */
//
// static int go_wc_DhCheckKeyPair(DhKey* key,
//         const byte* pub, word32 pubSz,
//         const byte* priv, word32 privSz) {
// #ifndef NO_DH
//     return wc_DhCheckKeyPair(key, pub, pubSz, priv, privSz);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* ---- Export raw parameters --------------------------------------------- */
//
// static int go_wc_DhExportParamsRaw(DhKey* dh,
//         byte* p, word32* pSz,
//         byte* q, word32* qSz,
//         byte* g, word32* gSz) {
// #ifndef NO_DH
//     return wc_DhExportParamsRaw(dh, p, pSz, q, qSz, g, gSz);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
//
// /* ---- Combined set + check ---------------------------------------------- */
//
// static int go_wc_DhSetCheckKey(DhKey* key,
//         const byte* p, word32 pSz,
//         const byte* g, word32 gSz,
//         const byte* q, word32 qSz,
//         int trusted, WC_RNG* rng) {
// #ifndef NO_DH
//     return wc_DhSetCheckKey(key, p, pSz, g, gSz, q, qSz, trusted, rng);
// #else
//     return NOT_COMPILED_IN;
// #endif
// }
import "C"
import (
	"unsafe"
)

// DhKey is a type alias for the wolfSSL DhKey struct.
type DhKey = C.DhKey

// Wc_InitDhKey initialises a DhKey using the default heap and device.
func Wc_InitDhKey(key *C.DhKey) int {
	return int(C.go_wc_InitDhKey(key))
}

// Wc_InitDhKey_ex initialises a DhKey with an explicit heap pointer and device
// identifier.
func Wc_InitDhKey_ex(key *C.DhKey, heap unsafe.Pointer, devId int) int {
	return int(C.go_wc_InitDhKey_ex(key, heap, C.int(devId)))
}

// Wc_FreeDhKey releases resources held by a DhKey.
func Wc_FreeDhKey(key *C.DhKey) int {
	return int(C.go_wc_FreeDhKey(key))
}

// Wc_DhSetKey loads the DH group parameters prime p and generator g into key.
// p and g must be big-endian byte arrays.
func Wc_DhSetKey(key *C.DhKey, p []byte, pSz int, g []byte, gSz int) int {
	if pSz < 0 || pSz > len(p) {
		return BAD_FUNC_ARG
	}
	if gSz < 0 || gSz > len(g) {
		return BAD_FUNC_ARG
	}
	if len(p) == 0 || len(g) == 0 {
		return BAD_FUNC_ARG
	}
	return int(C.go_wc_DhSetKey(key,
		(*C.byte)(unsafe.Pointer(&p[0])), C.word32(pSz),
		(*C.byte)(unsafe.Pointer(&g[0])), C.word32(gSz)))
}

// Wc_DhSetKey_ex loads p, g, and the optional subgroup order q into key.
// Pass a nil or zero-length q slice and qSz=0 to omit q.
func Wc_DhSetKey_ex(key *C.DhKey, p []byte, pSz int, g []byte, gSz int, q []byte, qSz int) int {
	if pSz < 0 || pSz > len(p) {
		return BAD_FUNC_ARG
	}
	if gSz < 0 || gSz > len(g) {
		return BAD_FUNC_ARG
	}
	if qSz < 0 || qSz > len(q) {
		return BAD_FUNC_ARG
	}
	if len(p) == 0 || len(g) == 0 {
		return BAD_FUNC_ARG
	}
	var qPtr *C.byte
	if qSz > 0 && len(q) > 0 {
		qPtr = (*C.byte)(unsafe.Pointer(&q[0]))
	}
	return int(C.go_wc_DhSetKey_ex(key,
		(*C.byte)(unsafe.Pointer(&p[0])), C.word32(pSz),
		(*C.byte)(unsafe.Pointer(&g[0])), C.word32(gSz),
		qPtr, C.word32(qSz)))
}

// Wc_DhGenerateKeyPair generates a DH key pair using rng.
//
// priv and pub are output buffers sized by the caller; privSz and pubSz are
// in/out: on entry they hold the buffer capacity, on return they hold the
// actual number of bytes written.
//
// Note: the C API places priv/privSz before pub/pubSz.
func Wc_DhGenerateKeyPair(key *C.DhKey, rng *C.struct_WC_RNG,
	priv []byte, privSz *int,
	pub []byte, pubSz *int) int {
	if privSz == nil || pubSz == nil {
		return BAD_FUNC_ARG
	}
	if *privSz < 0 || *privSz > len(priv) {
		return BAD_FUNC_ARG
	}
	if *pubSz < 0 || *pubSz > len(pub) {
		return BAD_FUNC_ARG
	}
	if len(priv) == 0 || len(pub) == 0 {
		return BAD_FUNC_ARG
	}
	cPrivSz := C.word32(*privSz)
	cPubSz := C.word32(*pubSz)
	ret := int(C.go_wc_DhGenerateKeyPair(key, rng,
		(*C.byte)(unsafe.Pointer(&priv[0])), &cPrivSz,
		(*C.byte)(unsafe.Pointer(&pub[0])), &cPubSz))
	*privSz = int(cPrivSz)
	*pubSz = int(cPubSz)
	return ret
}

// Wc_DhAgree computes the DH shared secret.
//
// agree is the output buffer; agreeSz is in/out (capacity → actual length).
// priv is the local private key (privSz bytes).
// pub is the remote public key (pubSz bytes).
func Wc_DhAgree(key *C.DhKey,
	agree []byte, agreeSz *int,
	priv []byte, privSz int,
	pub []byte, pubSz int) int {
	if agreeSz == nil {
		return BAD_FUNC_ARG
	}
	if *agreeSz < 0 || *agreeSz > len(agree) {
		return BAD_FUNC_ARG
	}
	if privSz < 0 || privSz > len(priv) {
		return BAD_FUNC_ARG
	}
	if pubSz < 0 || pubSz > len(pub) {
		return BAD_FUNC_ARG
	}
	if len(agree) == 0 || len(priv) == 0 || len(pub) == 0 {
		return BAD_FUNC_ARG
	}
	cAgreeSz := C.word32(*agreeSz)
	ret := int(C.go_wc_DhAgree(key,
		(*C.byte)(unsafe.Pointer(&agree[0])), &cAgreeSz,
		(*C.byte)(unsafe.Pointer(&priv[0])), C.word32(privSz),
		(*C.byte)(unsafe.Pointer(&pub[0])), C.word32(pubSz)))
	*agreeSz = int(cAgreeSz)
	return ret
}

// Wc_DhCheckPubKey verifies that pub is a valid public key for the group
// parameters already loaded into key.
func Wc_DhCheckPubKey(key *C.DhKey, pub []byte, pubSz int) int {
	if pubSz < 0 || pubSz > len(pub) {
		return BAD_FUNC_ARG
	}
	if len(pub) == 0 {
		return BAD_FUNC_ARG
	}
	return int(C.go_wc_DhCheckPubKey(key,
		(*C.byte)(unsafe.Pointer(&pub[0])), C.word32(pubSz)))
}

// Wc_DhCheckPubKey_ex verifies pub against the explicitly supplied prime.
func Wc_DhCheckPubKey_ex(key *C.DhKey,
	pub []byte, pubSz int,
	prime []byte, primeSz int) int {
	if pubSz < 0 || pubSz > len(pub) {
		return BAD_FUNC_ARG
	}
	if primeSz < 0 || primeSz > len(prime) {
		return BAD_FUNC_ARG
	}
	if len(pub) == 0 || len(prime) == 0 {
		return BAD_FUNC_ARG
	}
	return int(C.go_wc_DhCheckPubKey_ex(key,
		(*C.byte)(unsafe.Pointer(&pub[0])), C.word32(pubSz),
		(*C.byte)(unsafe.Pointer(&prime[0])), C.word32(primeSz)))
}

// Wc_DhCheckPrivKey verifies that priv is a valid private key for the group
// parameters already loaded into key.
func Wc_DhCheckPrivKey(key *C.DhKey, priv []byte, privSz int) int {
	if privSz < 0 || privSz > len(priv) {
		return BAD_FUNC_ARG
	}
	if len(priv) == 0 {
		return BAD_FUNC_ARG
	}
	return int(C.go_wc_DhCheckPrivKey(key,
		(*C.byte)(unsafe.Pointer(&priv[0])), C.word32(privSz)))
}

// Wc_DhCheckPrivKey_ex verifies priv against the explicitly supplied prime.
func Wc_DhCheckPrivKey_ex(key *C.DhKey,
	priv []byte, privSz int,
	prime []byte, primeSz int) int {
	if privSz < 0 || privSz > len(priv) {
		return BAD_FUNC_ARG
	}
	if primeSz < 0 || primeSz > len(prime) {
		return BAD_FUNC_ARG
	}
	if len(priv) == 0 || len(prime) == 0 {
		return BAD_FUNC_ARG
	}
	return int(C.go_wc_DhCheckPrivKey_ex(key,
		(*C.byte)(unsafe.Pointer(&priv[0])), C.word32(privSz),
		(*C.byte)(unsafe.Pointer(&prime[0])), C.word32(primeSz)))
}

// Wc_DhCheckKeyPair checks that pub and priv form a valid DH key pair under
// the group parameters already loaded into key.
func Wc_DhCheckKeyPair(key *C.DhKey,
	pub []byte, pubSz int,
	priv []byte, privSz int) int {
	if pubSz < 0 || pubSz > len(pub) {
		return BAD_FUNC_ARG
	}
	if privSz < 0 || privSz > len(priv) {
		return BAD_FUNC_ARG
	}
	if len(pub) == 0 || len(priv) == 0 {
		return BAD_FUNC_ARG
	}
	return int(C.go_wc_DhCheckKeyPair(key,
		(*C.byte)(unsafe.Pointer(&pub[0])), C.word32(pubSz),
		(*C.byte)(unsafe.Pointer(&priv[0])), C.word32(privSz)))
}

// Wc_DhExportParamsRaw exports the raw big-endian p, q, and g parameters from
// a DhKey.
//
// p, q, g are output buffers; pSz, qSz, gSz are in/out size parameters.
// Pass nil q and qSz pointing to 0 to skip exporting q (the C API accepts NULL
// for q/qSz when q is not needed).
func Wc_DhExportParamsRaw(dh *C.DhKey,
	p []byte, pSz *int,
	q []byte, qSz *int,
	g []byte, gSz *int) int {
	if pSz == nil || gSz == nil {
		return BAD_FUNC_ARG
	}
	if *pSz < 0 || *pSz > len(p) {
		return BAD_FUNC_ARG
	}
	if *gSz < 0 || *gSz > len(g) {
		return BAD_FUNC_ARG
	}
	if len(p) == 0 || len(g) == 0 {
		return BAD_FUNC_ARG
	}

	cPSz := C.word32(*pSz)
	cGSz := C.word32(*gSz)

	var qPtr *C.byte
	var cQSz C.word32
	var cQSzPtr *C.word32
	if qSz != nil && *qSz > 0 && len(q) > 0 {
		if *qSz > len(q) {
			return BAD_FUNC_ARG
		}
		qPtr = (*C.byte)(unsafe.Pointer(&q[0]))
		cQSz = C.word32(*qSz)
		cQSzPtr = &cQSz
	}

	ret := int(C.go_wc_DhExportParamsRaw(dh,
		(*C.byte)(unsafe.Pointer(&p[0])), &cPSz,
		qPtr, cQSzPtr,
		(*C.byte)(unsafe.Pointer(&g[0])), &cGSz))
	*pSz = int(cPSz)
	*gSz = int(cGSz)
	if qSz != nil && cQSzPtr != nil {
		*qSz = int(cQSz)
	}
	return ret
}

// Wc_DhSetCheckKey loads DH parameters into key and validates them with rng.
//
// q is optional: pass nil and qSz=0 to omit.
// trusted=1 skips the full primality check (use only for known-good FFDHE
// groups); trusted=0 performs the full validation.
func Wc_DhSetCheckKey(key *C.DhKey,
	p []byte, pSz int,
	g []byte, gSz int,
	q []byte, qSz int,
	trusted int, rng *C.struct_WC_RNG) int {
	if pSz < 0 || pSz > len(p) {
		return BAD_FUNC_ARG
	}
	if gSz < 0 || gSz > len(g) {
		return BAD_FUNC_ARG
	}
	if qSz < 0 || qSz > len(q) {
		return BAD_FUNC_ARG
	}
	if len(p) == 0 || len(g) == 0 {
		return BAD_FUNC_ARG
	}
	var qPtr *C.byte
	if qSz > 0 && len(q) > 0 {
		qPtr = (*C.byte)(unsafe.Pointer(&q[0]))
	}
	return int(C.go_wc_DhSetCheckKey(key,
		(*C.byte)(unsafe.Pointer(&p[0])), C.word32(pSz),
		(*C.byte)(unsafe.Pointer(&g[0])), C.word32(gSz),
		qPtr, C.word32(qSz),
		C.int(trusted), rng))
}
