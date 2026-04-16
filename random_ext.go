/* random_ext.go
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
// #include <wolfssl/wolfcrypt/random.h>
//
// /* wc_RNG_GenerateByte is defined as a macro to NOT_COMPILED_IN when
//  * WC_NO_RNG is set, so we wrap it in a plain C function to avoid
//  * CGO macro expansion issues. */
// #ifdef WC_NO_RNG
// static int wc_rng_generate_byte_wrap(WC_RNG* rng, byte* b) {
//     (void)rng; (void)b;
//     return -174;
// }
// static int wc_rng_health_test_wrap(int reseed,
//                                    const byte* seedA, word32 seedASz,
//                                    const byte* seedB, word32 seedBSz,
//                                    byte* output, word32 outputSz) {
//     (void)reseed;
//     (void)seedA; (void)seedASz;
//     (void)seedB; (void)seedBSz;
//     (void)output; (void)outputSz;
//     return -174;
// }
// static int wc_rng_drbg_reseed_wrap(WC_RNG* rng, const byte* seed,
//                                    word32 seedSz) {
//     (void)rng; (void)seed; (void)seedSz;
//     return -174;
// }
// #else
// static int wc_rng_generate_byte_wrap(WC_RNG* rng, byte* b) {
//     return wc_RNG_GenerateByte(rng, b);
// }
// #ifdef HAVE_HASHDRBG
// static int wc_rng_health_test_wrap(int reseed,
//                                    const byte* seedA, word32 seedASz,
//                                    const byte* seedB, word32 seedBSz,
//                                    byte* output, word32 outputSz) {
//     return wc_RNG_HealthTest(reseed, seedA, seedASz, seedB, seedBSz,
//                              output, outputSz);
// }
// static int wc_rng_drbg_reseed_wrap(WC_RNG* rng, const byte* seed,
//                                    word32 seedSz) {
//     return wc_RNG_DRBG_Reseed(rng, seed, seedSz);
// }
// #else
// static int wc_rng_health_test_wrap(int reseed,
//                                    const byte* seedA, word32 seedASz,
//                                    const byte* seedB, word32 seedBSz,
//                                    byte* output, word32 outputSz) {
//     (void)reseed;
//     (void)seedA; (void)seedASz;
//     (void)seedB; (void)seedBSz;
//     (void)output; (void)outputSz;
//     return -174;
// }
// static int wc_rng_drbg_reseed_wrap(WC_RNG* rng, const byte* seed,
//                                    word32 seedSz) {
//     (void)rng; (void)seed; (void)seedSz;
//     return -174;
// }
// #endif /* HAVE_HASHDRBG */
// #endif /* WC_NO_RNG */
import "C"
import (
	"unsafe"
)

// Wc_RNG_GenerateByte fills b with a single random byte from rng.
// Returns 0 on success, or a negative wolfSSL error code on failure.
func Wc_RNG_GenerateByte(rng *C.struct_WC_RNG, b *byte) int {
	if b == nil {
		return BAD_FUNC_ARG
	}
	return int(C.wc_rng_generate_byte_wrap(rng, (*C.uchar)(unsafe.Pointer(b))))
}

// Wc_RNG_HealthTest runs the NIST SP 800-90A health test on the Hash-DRBG.
// reseed selects which DRBG path to exercise: 0 = instantiate only,
// 1 = instantiate + reseed.  seedB and seedBSz are used only when reseed == 1.
// output must be at least RNG_HEALTH_TEST_CHECK_SIZE (4 * SHA256_DIGEST_SIZE)
// bytes.  Returns 0 on success, or a negative error code on failure or
// if HAVE_HASHDRBG is not compiled in.
func Wc_RNG_HealthTest(reseed int, seedA []byte, seedB []byte, output []byte) int {
	if len(seedA) == 0 || len(output) == 0 {
		return BAD_FUNC_ARG
	}
	var seedBPtr *C.uchar
	var seedBSz C.word32
	if len(seedB) > 0 {
		seedBPtr = (*C.uchar)(unsafe.Pointer(&seedB[0]))
		seedBSz = C.word32(len(seedB))
	}
	return int(C.wc_rng_health_test_wrap(
		C.int(reseed),
		(*C.uchar)(unsafe.Pointer(&seedA[0])), C.word32(len(seedA)),
		seedBPtr, seedBSz,
		(*C.uchar)(unsafe.Pointer(&output[0])), C.word32(len(output)),
	))
}

// Wc_RNG_DRBG_Reseed manually reseeds the Hash-DRBG with the provided entropy.
// Returns 0 on success, or a negative error code on failure or if
// HAVE_HASHDRBG is not compiled in.
func Wc_RNG_DRBG_Reseed(rng *C.struct_WC_RNG, seed []byte) int {
	if len(seed) == 0 {
		return BAD_FUNC_ARG
	}
	return int(C.wc_rng_drbg_reseed_wrap(
		rng,
		(*C.uchar)(unsafe.Pointer(&seed[0])), C.word32(len(seed)),
	))
}
