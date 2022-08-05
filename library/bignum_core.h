/**
 *  Internal bignum functions
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#ifndef MBEDTLS_BIGNUM_CORE_H
#define MBEDTLS_BIGNUM_CORE_H

#include "common.h"

#if defined(MBEDTLS_BIGNUM_C)
#include "mbedtls/bignum.h"
#endif

/**
 * \brief Montgomery multiplication: X = A * B * R^-1 mod N  (HAC 14.36)
 *
 * \param[out]     X      The destination MPI, as a little-endian array of
 *                        length \p n.
 *                        On successful completion, X contains the result of
 *                        the multiplication A * B * R^-1 mod N where
 *                        R = (2^ciL)^n.
 * \param[in]      A      Little-endian presentation of first operand.
 *                        Must have exactly \p n limbs.
 * \param[in]      B      Little-endian presentation of second operand.
 * \param[in]      B_len  The number of limbs in \p B.
 * \param[in]      N      Little-endian presentation of the modulus.
 *                        This must be odd and have exactly \p n limbs.
 * \param[in]      n      The number of limbs in \p X, \p A, \p N.
 * \param          mm     The Montgomery constant for \p N: -N^-1 mod 2^ciL.
 *                        This can be calculated by `mpi_montg_init()`.
 * \param[in,out]  T      Temporary storage of size at least 2*n+1 limbs.
 *                        Its initial content is unused and
 *                        its final content is indeterminate.
 */
void mbedtls_mpi_core_montmul( mbedtls_mpi_uint *X,
                               const mbedtls_mpi_uint *A,
                               const mbedtls_mpi_uint *B, size_t B_len,
                               const mbedtls_mpi_uint *N, size_t n,
                               mbedtls_mpi_uint mm, mbedtls_mpi_uint *T );

/**
 * \brief Perform a known-size multiply accumulate operation: d += b * s
 *
 * \param[in,out] d     The pointer to the (little-endian) array
 *                      representing the bignum to accumulate onto.
 * \param d_len         The number of limbs of \p d. This must be
 *                      at least \p s_len.
 * \param[in] s         The pointer to the (little-endian) array
 *                      representing the bignum to multiply with.
 *                      This may be the same as \p d. Otherwise,
 *                      it must be disjoint from \p d.
 * \param s_len         The number of limbs of \p s.
 * \param b             A scalar to multiply with.
 *
 * \return c            The carry at the end of the operation.
 */
mbedtls_mpi_uint mbedtls_mpi_core_mla( mbedtls_mpi_uint *d, size_t d_len,
                                       const mbedtls_mpi_uint *s, size_t s_len,
                                       mbedtls_mpi_uint b );

/**
 * \brief Subtract two known-size large unsigned integers, returning the borrow.
 *
 * Calculate l - r where l and r have the same size.
 * This function operates modulo (2^ciL)^n and returns the carry
 * (1 if there was a wraparound, i.e. if `l < r`, and 0 otherwise).
 *
 * d may be aliased to l or r.
 *
 * \param[out] d        The result of the subtraction.
 * \param[in] l         Little-endian presentation of left operand.
 * \param[in] r         Little-endian presentation of right operand.
 * \param n             Number of limbs of \p d, \p l and \p r.
 *
 * \return              1 if `l < r`.
 *                      0 if `l >= r`.
 */
mbedtls_mpi_uint mbedtls_mpi_core_sub( mbedtls_mpi_uint *d,
                                       const mbedtls_mpi_uint *l,
                                       const mbedtls_mpi_uint *r,
                                       size_t n );

/**
 * \brief Constant-time conditional addition of two known-size large unsigned
 *        integers, returning the carry.
 *
 * Functionally equivalent to
 *
 * ```
 * if( cond )
 *    d += r;
 * return carry;
 * ```
 *
 * \param[in,out] d     The pointer to the (little-endian) array
 *                      representing the bignum to accumulate onto.
 * \param[in] r         The pointer to the (little-endian) array
 *                      representing the bignum to conditionally add
 *                      to \p d. This must be disjoint from \p d.
 * \param n             Number of limbs of \p d and \p r.
 * \param cond          Condition bit dictating whether addition should
 *                      happen or not. This must be \c 0 or \c 1.
 *
 * \return              1 if `d + cond*r >= (2^{ciL})^n`, 0 otherwise.
 */
mbedtls_mpi_uint mbedtls_mpi_core_add_if( mbedtls_mpi_uint *d,
                                          const mbedtls_mpi_uint *r,
                                          size_t n,
                                          unsigned cond );

#endif /* MBEDTLS_BIGNUM_CORE_H */
