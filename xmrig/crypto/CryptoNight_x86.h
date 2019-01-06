/* XMRig
 * Copyright 2010      Jeff Garzik <jgarzik@pobox.com>
 * Copyright 2012-2014 pooler      <pooler@litecoinpool.org>
 * Copyright 2014      Lucas Jones <https://github.com/lucasjones>
 * Copyright 2014-2016 Wolf9466    <https://github.com/OhGodAPet>
 * Copyright 2016      Jay D Dee   <jayddee246@gmail.com>
 * Copyright 2017-2018 XMR-Stak    <https://github.com/fireice-uk>, <https://github.com/psychocrypt>
 * Copyright 2018      Lee Clagett <https://github.com/vtnerd>
 * Copyright 2018      SChernykh   <https://github.com/SChernykh>
 * Copyright 2016-2018 XMRig       <https://github.com/xmrig>, <support@xmrig.com>
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef XMRIG_CRYPTONIGHT_X86_H
#define XMRIG_CRYPTONIGHT_X86_H


#ifdef __GNUC__
#   include <x86intrin.h>
#else
#   include <intrin.h>
#   define __restrict__ __restrict
#endif


#include "common/crypto/keccak.h"
#include "crypto/CryptoNight.h"
#include "crypto/CryptoNight_constants.h"
#include "crypto/CryptoNight_monero.h"
#include "crypto/soft_aes.h"


extern "C"
{
#include "crypto/c_groestl.h"
#include "crypto/c_blake256.h"
#include "crypto/c_jh.h"
#include "crypto/c_skein.h"
}

#define U64(x) ((uint64_t *) (x))
#define R128(x) ((__m128i *) (x))
#define state_index(x) (((*((uint64_t *)x) >> 4) & (65535)) << 4)

static inline void do_blake_hash(const uint8_t *input, size_t len, uint8_t *output) {
    blake256_hash(output, input, len);
}


static inline void do_groestl_hash(const uint8_t *input, size_t len, uint8_t *output) {
    groestl(input, len * 8, output);
}


static inline void do_jh_hash(const uint8_t *input, size_t len, uint8_t *output) {
    jh_hash(32 * 8, input, 8 * len, output);
}


static inline void do_skein_hash(const uint8_t *input, size_t len, uint8_t *output) {
    xmr_skein(input, output);
}


void (* const extra_hashes[4])(const uint8_t *, size_t, uint8_t *) = {do_blake_hash, do_groestl_hash, do_jh_hash, do_skein_hash};


#if defined(__x86_64__) || defined(_M_AMD64)
#   ifdef __GNUC__
static inline uint64_t __umul128(uint64_t a, uint64_t b, uint64_t* hi)
{
    unsigned __int128 r = (unsigned __int128) a * (unsigned __int128) b;
    *hi = r >> 64;
    return (uint64_t) r;
}
#   else
    #define __umul128 _umul128
#   endif
#elif defined(__i386__) || defined(_M_IX86)
static inline int64_t _mm_cvtsi128_si64(__m128i a)
{
    return ((uint64_t)(uint32_t)_mm_cvtsi128_si32(a) | ((uint64_t)(uint32_t)_mm_cvtsi128_si32(_mm_srli_si128(a, 4)) << 32));
}

static inline __m128i _mm_cvtsi64_si128(int64_t a) {
    return _mm_set_epi64x(0, a);
}

static inline uint64_t __umul128(uint64_t multiplier, uint64_t multiplicand, uint64_t *product_hi) {
    // multiplier   = ab = a * 2^32 + b
    // multiplicand = cd = c * 2^32 + d
    // ab * cd = a * c * 2^64 + (a * d + b * c) * 2^32 + b * d
    uint64_t a = multiplier >> 32;
    uint64_t b = multiplier & 0xFFFFFFFF;
    uint64_t c = multiplicand >> 32;
    uint64_t d = multiplicand & 0xFFFFFFFF;

    //uint64_t ac = a * c;
    uint64_t ad = a * d;
    //uint64_t bc = b * c;
    uint64_t bd = b * d;

    uint64_t adbc = ad + (b * c);
    uint64_t adbc_carry = adbc < ad ? 1 : 0;

    // multiplier * multiplicand = product_hi * 2^64 + product_lo
    uint64_t product_lo = bd + (adbc << 32);
    uint64_t product_lo_carry = product_lo < bd ? 1 : 0;
    *product_hi = (a * c) + (adbc >> 32) + (adbc_carry << 32) + product_lo_carry;

    return product_lo;
}
#endif


// This will shift and xor tmp1 into itself as 4 32-bit vals such as
// sl_xor(a1 a2 a3 a4) = a1 (a2^a1) (a3^a2^a1) (a4^a3^a2^a1)
static inline __m128i sl_xor(__m128i tmp1)
{
    __m128i tmp4;
    tmp4 = _mm_slli_si128(tmp1, 0x04);
    tmp1 = _mm_xor_si128(tmp1, tmp4);
    tmp4 = _mm_slli_si128(tmp4, 0x04);
    tmp1 = _mm_xor_si128(tmp1, tmp4);
    tmp4 = _mm_slli_si128(tmp4, 0x04);
    tmp1 = _mm_xor_si128(tmp1, tmp4);
    return tmp1;
}


template<uint8_t rcon>
static inline void aes_genkey_sub(__m128i* xout0, __m128i* xout2)
{
    __m128i xout1 = _mm_aeskeygenassist_si128(*xout2, rcon);
    xout1  = _mm_shuffle_epi32(xout1, 0xFF); // see PSHUFD, set all elems to 4th elem
    *xout0 = sl_xor(*xout0);
    *xout0 = _mm_xor_si128(*xout0, xout1);
    xout1  = _mm_aeskeygenassist_si128(*xout0, 0x00);
    xout1  = _mm_shuffle_epi32(xout1, 0xAA); // see PSHUFD, set all elems to 3rd elem
    *xout2 = sl_xor(*xout2);
    *xout2 = _mm_xor_si128(*xout2, xout1);
}


template<uint8_t rcon>
static inline void soft_aes_genkey_sub(__m128i* xout0, __m128i* xout2)
{
    __m128i xout1 = soft_aeskeygenassist<rcon>(*xout2);
    xout1  = _mm_shuffle_epi32(xout1, 0xFF); // see PSHUFD, set all elems to 4th elem
    *xout0 = sl_xor(*xout0);
    *xout0 = _mm_xor_si128(*xout0, xout1);
    xout1  = soft_aeskeygenassist<0x00>(*xout0);
    xout1  = _mm_shuffle_epi32(xout1, 0xAA); // see PSHUFD, set all elems to 3rd elem
    *xout2 = sl_xor(*xout2);
    *xout2 = _mm_xor_si128(*xout2, xout1);
}


template<bool SOFT_AES>
static inline void aes_genkey(const __m128i* memory, __m128i* k0, __m128i* k1, __m128i* k2, __m128i* k3, __m128i* k4, __m128i* k5, __m128i* k6, __m128i* k7, __m128i* k8, __m128i* k9)
{
    __m128i xout0 = _mm_load_si128(memory);
    __m128i xout2 = _mm_load_si128(memory + 1);
    *k0 = xout0;
    *k1 = xout2;

    SOFT_AES ? soft_aes_genkey_sub<0x01>(&xout0, &xout2) : aes_genkey_sub<0x01>(&xout0, &xout2);
    *k2 = xout0;
    *k3 = xout2;

    SOFT_AES ? soft_aes_genkey_sub<0x02>(&xout0, &xout2) : aes_genkey_sub<0x02>(&xout0, &xout2);
    *k4 = xout0;
    *k5 = xout2;

    SOFT_AES ? soft_aes_genkey_sub<0x04>(&xout0, &xout2) : aes_genkey_sub<0x04>(&xout0, &xout2);
    *k6 = xout0;
    *k7 = xout2;

    SOFT_AES ? soft_aes_genkey_sub<0x08>(&xout0, &xout2) : aes_genkey_sub<0x08>(&xout0, &xout2);
    *k8 = xout0;
    *k9 = xout2;
}


template<bool SOFT_AES>
static inline void aes_round(__m128i key, __m128i* x0, __m128i* x1, __m128i* x2, __m128i* x3, __m128i* x4, __m128i* x5, __m128i* x6, __m128i* x7)
{
    if (SOFT_AES) {
        *x0 = soft_aesenc((uint32_t*)x0, key);
        *x1 = soft_aesenc((uint32_t*)x1, key);
        *x2 = soft_aesenc((uint32_t*)x2, key);
        *x3 = soft_aesenc((uint32_t*)x3, key);
        *x4 = soft_aesenc((uint32_t*)x4, key);
        *x5 = soft_aesenc((uint32_t*)x5, key);
        *x6 = soft_aesenc((uint32_t*)x6, key);
        *x7 = soft_aesenc((uint32_t*)x7, key);
    }
    else {
        *x0 = _mm_aesenc_si128(*x0, key);
        *x1 = _mm_aesenc_si128(*x1, key);
        *x2 = _mm_aesenc_si128(*x2, key);
        *x3 = _mm_aesenc_si128(*x3, key);
        *x4 = _mm_aesenc_si128(*x4, key);
        *x5 = _mm_aesenc_si128(*x5, key);
        *x6 = _mm_aesenc_si128(*x6, key);
        *x7 = _mm_aesenc_si128(*x7, key);
    }
}


inline void mix_and_propagate(__m128i& x0, __m128i& x1, __m128i& x2, __m128i& x3, __m128i& x4, __m128i& x5, __m128i& x6, __m128i& x7)
{
    __m128i tmp0 = x0;
    x0 = _mm_xor_si128(x0, x1);
    x1 = _mm_xor_si128(x1, x2);
    x2 = _mm_xor_si128(x2, x3);
    x3 = _mm_xor_si128(x3, x4);
    x4 = _mm_xor_si128(x4, x5);
    x5 = _mm_xor_si128(x5, x6);
    x6 = _mm_xor_si128(x6, x7);
    x7 = _mm_xor_si128(x7, tmp0);
}


template<xmrig::Algo ALGO, size_t MEM, bool SOFT_AES>
static inline void cn_explode_scratchpad(const __m128i *input, __m128i *output)
{
    __m128i xin0, xin1, xin2, xin3, xin4, xin5, xin6, xin7;
    __m128i k0, k1, k2, k3, k4, k5, k6, k7, k8, k9;

    aes_genkey<SOFT_AES>(input, &k0, &k1, &k2, &k3, &k4, &k5, &k6, &k7, &k8, &k9);

    xin0 = _mm_load_si128(input + 4);
    xin1 = _mm_load_si128(input + 5);
    xin2 = _mm_load_si128(input + 6);
    xin3 = _mm_load_si128(input + 7);
    xin4 = _mm_load_si128(input + 8);
    xin5 = _mm_load_si128(input + 9);
    xin6 = _mm_load_si128(input + 10);
    xin7 = _mm_load_si128(input + 11);

    if (ALGO == xmrig::CRYPTONIGHT_HEAVY) {
        for (size_t i = 0; i < 16; i++) {
            aes_round<SOFT_AES>(k0, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
            aes_round<SOFT_AES>(k1, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
            aes_round<SOFT_AES>(k2, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
            aes_round<SOFT_AES>(k3, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
            aes_round<SOFT_AES>(k4, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
            aes_round<SOFT_AES>(k5, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
            aes_round<SOFT_AES>(k6, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
            aes_round<SOFT_AES>(k7, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
            aes_round<SOFT_AES>(k8, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
            aes_round<SOFT_AES>(k9, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);

            mix_and_propagate(xin0, xin1, xin2, xin3, xin4, xin5, xin6, xin7);
        }
    }

    for (size_t i = 0; i < MEM / sizeof(__m128i); i += 8) {
        aes_round<SOFT_AES>(k0, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        aes_round<SOFT_AES>(k1, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        aes_round<SOFT_AES>(k2, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        aes_round<SOFT_AES>(k3, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        aes_round<SOFT_AES>(k4, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        aes_round<SOFT_AES>(k5, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        aes_round<SOFT_AES>(k6, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        aes_round<SOFT_AES>(k7, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        aes_round<SOFT_AES>(k8, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        aes_round<SOFT_AES>(k9, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);

        _mm_store_si128(output + i + 0, xin0);
        _mm_store_si128(output + i + 1, xin1);
        _mm_store_si128(output + i + 2, xin2);
        _mm_store_si128(output + i + 3, xin3);
        _mm_store_si128(output + i + 4, xin4);
        _mm_store_si128(output + i + 5, xin5);
        _mm_store_si128(output + i + 6, xin6);
        _mm_store_si128(output + i + 7, xin7);
    }
}


template<xmrig::Algo ALGO, size_t MEM, bool SOFT_AES>
static inline void cn_implode_scratchpad(const __m128i *input, __m128i *output)
{
    __m128i xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7;
    __m128i k0, k1, k2, k3, k4, k5, k6, k7, k8, k9;

    aes_genkey<SOFT_AES>(output + 2, &k0, &k1, &k2, &k3, &k4, &k5, &k6, &k7, &k8, &k9);

    xout0 = _mm_load_si128(output + 4);
    xout1 = _mm_load_si128(output + 5);
    xout2 = _mm_load_si128(output + 6);
    xout3 = _mm_load_si128(output + 7);
    xout4 = _mm_load_si128(output + 8);
    xout5 = _mm_load_si128(output + 9);
    xout6 = _mm_load_si128(output + 10);
    xout7 = _mm_load_si128(output + 11);

    for (size_t i = 0; i < MEM / sizeof(__m128i); i += 8)
    {
        xout0 = _mm_xor_si128(_mm_load_si128(input + i + 0), xout0);
        xout1 = _mm_xor_si128(_mm_load_si128(input + i + 1), xout1);
        xout2 = _mm_xor_si128(_mm_load_si128(input + i + 2), xout2);
        xout3 = _mm_xor_si128(_mm_load_si128(input + i + 3), xout3);
        xout4 = _mm_xor_si128(_mm_load_si128(input + i + 4), xout4);
        xout5 = _mm_xor_si128(_mm_load_si128(input + i + 5), xout5);
        xout6 = _mm_xor_si128(_mm_load_si128(input + i + 6), xout6);
        xout7 = _mm_xor_si128(_mm_load_si128(input + i + 7), xout7);

        aes_round<SOFT_AES>(k0, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        aes_round<SOFT_AES>(k1, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        aes_round<SOFT_AES>(k2, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        aes_round<SOFT_AES>(k3, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        aes_round<SOFT_AES>(k4, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        aes_round<SOFT_AES>(k5, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        aes_round<SOFT_AES>(k6, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        aes_round<SOFT_AES>(k7, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        aes_round<SOFT_AES>(k8, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        aes_round<SOFT_AES>(k9, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);

        if (ALGO == xmrig::CRYPTONIGHT_HEAVY) {
            mix_and_propagate(xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7);
        }
    }

    if (ALGO == xmrig::CRYPTONIGHT_HEAVY) {
        for (size_t i = 0; i < MEM / sizeof(__m128i); i += 8) {
            xout0 = _mm_xor_si128(_mm_load_si128(input + i + 0), xout0);
            xout1 = _mm_xor_si128(_mm_load_si128(input + i + 1), xout1);
            xout2 = _mm_xor_si128(_mm_load_si128(input + i + 2), xout2);
            xout3 = _mm_xor_si128(_mm_load_si128(input + i + 3), xout3);
            xout4 = _mm_xor_si128(_mm_load_si128(input + i + 4), xout4);
            xout5 = _mm_xor_si128(_mm_load_si128(input + i + 5), xout5);
            xout6 = _mm_xor_si128(_mm_load_si128(input + i + 6), xout6);
            xout7 = _mm_xor_si128(_mm_load_si128(input + i + 7), xout7);

            aes_round<SOFT_AES>(k0, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k1, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k2, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k3, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k4, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k5, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k6, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k7, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k8, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k9, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);

            mix_and_propagate(xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7);
        }

        for (size_t i = 0; i < 16; i++) {
            aes_round<SOFT_AES>(k0, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k1, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k2, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k3, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k4, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k5, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k6, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k7, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k8, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
            aes_round<SOFT_AES>(k9, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);

            mix_and_propagate(xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7);
        }
    }

    _mm_store_si128(output + 4, xout0);
    _mm_store_si128(output + 5, xout1);
    _mm_store_si128(output + 6, xout2);
    _mm_store_si128(output + 7, xout3);
    _mm_store_si128(output + 8, xout4);
    _mm_store_si128(output + 9, xout5);
    _mm_store_si128(output + 10, xout6);
    _mm_store_si128(output + 11, xout7);
}


static inline __m128i aes_round_tweak_div(const __m128i &in, const __m128i &key)
{
    alignas(16) uint32_t k[4];
    alignas(16) uint32_t x[4];

    _mm_store_si128((__m128i*) k, key);
    _mm_store_si128((__m128i*) x, _mm_xor_si128(in, _mm_set_epi64x(0xffffffffffffffff, 0xffffffffffffffff)));

    #define BYTE(p, i) ((unsigned char*)&x[p])[i]
    k[0] ^= saes_table[0][BYTE(0, 0)] ^ saes_table[1][BYTE(1, 1)] ^ saes_table[2][BYTE(2, 2)] ^ saes_table[3][BYTE(3, 3)];
    x[0] ^= k[0];
    k[1] ^= saes_table[0][BYTE(1, 0)] ^ saes_table[1][BYTE(2, 1)] ^ saes_table[2][BYTE(3, 2)] ^ saes_table[3][BYTE(0, 3)];
    x[1] ^= k[1];
    k[2] ^= saes_table[0][BYTE(2, 0)] ^ saes_table[1][BYTE(3, 1)] ^ saes_table[2][BYTE(0, 2)] ^ saes_table[3][BYTE(1, 3)];
    x[2] ^= k[2];
    k[3] ^= saes_table[0][BYTE(3, 0)] ^ saes_table[1][BYTE(0, 1)] ^ saes_table[2][BYTE(1, 2)] ^ saes_table[3][BYTE(2, 3)];
    #undef BYTE

    return _mm_load_si128((__m128i*)k);
}


static inline __m128i int_sqrt_v2(const uint64_t n0)
{
    __m128d x = _mm_castsi128_pd(_mm_add_epi64(_mm_cvtsi64_si128(n0 >> 12), _mm_set_epi64x(0, 1023ULL << 52)));
    x = _mm_sqrt_sd(_mm_setzero_pd(), x);
    uint64_t r = static_cast<uint64_t>(_mm_cvtsi128_si64(_mm_castpd_si128(x)));

    const uint64_t s = r >> 20;
    r >>= 19;

    uint64_t x2 = (s - (1022ULL << 32)) * (r - s - (1022ULL << 32) + 1);
#   if (defined(_MSC_VER) || __GNUC__ > 7 || (__GNUC__ == 7 && __GNUC_MINOR__ > 1)) && (defined(__x86_64__) || defined(_M_AMD64))
    _addcarry_u64(_subborrow_u64(0, x2, n0, (unsigned long long int*)&x2), r, 0, (unsigned long long int*)&r);
#   else
    if (x2 < n0) ++r;
#   endif

    return _mm_cvtsi64_si128(r);
}


template<xmrig::Variant VARIANT>
static inline void cryptonight_monero_tweak(uint64_t* mem_out, const uint8_t* l, uint64_t idx, __m128i ax0, __m128i bx0, __m128i bx1, __m128i cx)
{
    if (VARIANT == xmrig::VARIANT_2) {
        VARIANT2_SHUFFLE(l, idx, ax0, bx0, bx1);
        _mm_store_si128((__m128i *)mem_out, _mm_xor_si128(bx0, cx));
    } else {
        __m128i tmp = _mm_xor_si128(bx0, cx);
        mem_out[0] = _mm_cvtsi128_si64(tmp);

        tmp = _mm_castps_si128(_mm_movehl_ps(_mm_castsi128_ps(tmp), _mm_castsi128_ps(tmp)));
        uint64_t vh = _mm_cvtsi128_si64(tmp);

        uint8_t x = static_cast<uint8_t>(vh >> 24);
        static const uint16_t table = 0x7531;
        const uint8_t index = (((x >> (VARIANT == xmrig::VARIANT_XTL ? 4 : 3)) & 6) | (x & 1)) << 1;
        vh ^= ((table >> index) & 0x3) << 28;

        mem_out[1] = vh;
    }
}


template<xmrig::Algo ALGO, bool SOFT_AES, xmrig::Variant VARIANT>
inline void cryptonight_single_hash(const uint8_t *__restrict__ input, size_t size, uint8_t *__restrict__ output, cryptonight_ctx **__restrict__ ctx)
{

    xmrig::keccak(input, size, ctx[0]->state);

    cn_explode_scratchpad<ALGO, 2097152, SOFT_AES>((__m128i*) ctx[0]->state, (__m128i*) ctx[0]->memory);

    const uint8_t* l0 = ctx[0]->memory;
    uint64_t* h0 = reinterpret_cast<uint64_t*>(ctx[0]->state);

    uint64_t c[2], c1[2]; 
    uint64_t al0 = h0[0] ^ h0[4];
    uint64_t ah0 = h0[1] ^ h0[5];

    uint64_t idx0 = al0;
    size_t ptr0;

    for(size_t i = 0; i < 0x200000; i++)
    {
        __m128i cx; 
        __m128i ax0 = _mm_set_epi64x(ah0, al0);
        ptr0 = state_index(l0[idx0 & 0x1FFFF0]);
        cx = _mm_load_si128((__m128i *) &l0[idx0 & 0x1FFFF0]);
        cx= SOFT_AES?soft_aesenc(cx, ax0):_mm_aesenc_si128(cx, ax0); 
        _mm_store_si128(R128(c), cx);  
        _mm_store_si128(R128(c1), _mm_load_si128(R128(ptr0))); 
        ptr0 = state_index(c); 
        c[0] ^= al0; c[1] ^= ah0; 
        _mm_store_si128((__m128i *)ptr0,_mm_load_si128(R128(c))); 
        ptr0 = state_index(c);
        _mm_store_si128((__m128i *)ptr0, _mm_load_si128(R128(c1))); 
        c1[0] ^= c[0]; c1[1] ^= c[1];
        ptr0 = state_index(c1);
        _mm_store_si128((__m128i *)ptr0, _mm_load_si128(R128(c1))); 
        uint64_t cl, ch;
        cl = ((uint64_t*)ptr0)[0]; 
        ch = ((uint64_t*)ptr0)[1];
        ((uint64_t*)ptr0)[0] = al0; 
        ((uint64_t*)ptr0)[1] = ah0; 
        al0 ^= cl; 
        ah0 ^= ch; 
        ax0 = _mm_set_epi64x(ah0, al0); 
        idx0 = al0;
    }
    cn_implode_scratchpad<ALGO, 2097152, SOFT_AES>((__m128i*) l0, (__m128i*) ctx[0]->state);

    xmrig::keccakf(h0, 24);
    extra_hashes[ctx[0]->state[0] & 3](ctx[0]->state, 200, output);
}


#ifndef XMRIG_NO_ASM
extern "C" void cnv2_mainloop_ivybridge_asm(cryptonight_ctx *ctx);
extern "C" void cnv2_mainloop_ryzen_asm(cryptonight_ctx *ctx);
extern "C" void cnv2_double_mainloop_sandybridge_asm(cryptonight_ctx* ctx0, cryptonight_ctx* ctx1);


template<xmrig::Algo ALGO, xmrig::Variant VARIANT, xmrig::Assembly ASM>
inline void cryptonight_single_hash_asm(const uint8_t *__restrict__ input, size_t size, uint8_t *__restrict__ output, cryptonight_ctx **__restrict__ ctx)
{
    constexpr size_t MEM = xmrig::cn_select_memory<ALGO>();

    xmrig::keccak(input, size, ctx[0]->state);
    cn_explode_scratchpad<ALGO, MEM, false>(reinterpret_cast<__m128i*>(ctx[0]->state), reinterpret_cast<__m128i*>(ctx[0]->memory));

    if (ASM == xmrig::ASM_INTEL) {
        cnv2_mainloop_ivybridge_asm(ctx[0]);
    }
    else {
        cnv2_mainloop_ryzen_asm(ctx[0]);
    }

    cn_implode_scratchpad<ALGO, MEM, false>(reinterpret_cast<__m128i*>(ctx[0]->memory), reinterpret_cast<__m128i*>(ctx[0]->state));
    xmrig::keccakf(reinterpret_cast<uint64_t*>(ctx[0]->state), 24);
    extra_hashes[ctx[0]->state[0] & 3](ctx[0]->state, 200, output);
}


template<xmrig::Algo ALGO, xmrig::Variant VARIANT, xmrig::Assembly ASM>
inline void cryptonight_double_hash_asm(const uint8_t *__restrict__ input, size_t size, uint8_t *__restrict__ output, cryptonight_ctx **__restrict__ ctx)
{

    xmrig::keccak(input,        size, ctx[0]->state);
    xmrig::keccak(input + size, size, ctx[1]->state);

    cn_explode_scratchpad<ALGO, 2097152, false>(reinterpret_cast<__m128i*>(ctx[0]->state), reinterpret_cast<__m128i*>(ctx[0]->memory));
    cn_explode_scratchpad<ALGO, 2097152, false>(reinterpret_cast<__m128i*>(ctx[1]->state), reinterpret_cast<__m128i*>(ctx[1]->memory));

    cnv2_double_mainloop_sandybridge_asm(ctx[0], ctx[1]);

    cn_implode_scratchpad<ALGO, 2097152, false>(reinterpret_cast<__m128i*>(ctx[0]->memory), reinterpret_cast<__m128i*>(ctx[0]->state));
    cn_implode_scratchpad<ALGO, 2097152, false>(reinterpret_cast<__m128i*>(ctx[1]->memory), reinterpret_cast<__m128i*>(ctx[1]->state));

    xmrig::keccakf(reinterpret_cast<uint64_t*>(ctx[0]->state), 24);
    xmrig::keccakf(reinterpret_cast<uint64_t*>(ctx[1]->state), 24);

    extra_hashes[ctx[0]->state[0] & 3](ctx[0]->state, 200, output);
    extra_hashes[ctx[1]->state[0] & 3](ctx[1]->state, 200, output + 32);
}
#endif


template<xmrig::Algo ALGO, bool SOFT_AES, xmrig::Variant VARIANT>
inline void cryptonight_double_hash(const uint8_t *__restrict__ input, size_t size, uint8_t *__restrict__ output, cryptonight_ctx **__restrict__ ctx)
{
    xmrig::keccak(input, size, ctx[0]->state);
    xmrig::keccak(input+size, size, ctx[1]->state);

    cn_explode_scratchpad<ALGO, 2097152, SOFT_AES>((__m128i*) ctx[0]->state, (__m128i*) ctx[0]->memory);
    cn_explode_scratchpad<ALGO, 2097152, SOFT_AES>((__m128i*) ctx[1]->state, (__m128i*) ctx[1]->memory);

    const uint8_t* l0 = ctx[0]->memory;
    const uint8_t* l1 = ctx[1]->memory;
    uint64_t* h0 = reinterpret_cast<uint64_t*>(ctx[0]->state);
    uint64_t* h1 = reinterpret_cast<uint64_t*>(ctx[1]->state);

    uint64_t ca[2], ca1[2]; 
    uint64_t cb[2], cb1[2]; 
    uint64_t al0 = h0[0] ^ h0[4];
    uint64_t ah0 = h0[1] ^ h0[5];
    uint64_t al1 = h1[0] ^ h1[4];
    uint64_t ah1 = h1[1] ^ h1[5];

    uint64_t idx0 = al0;
    uint64_t idx1 = al1;
    size_t ptr0;
    size_t ptr1;

    for(size_t i = 0; i < 0x200000; i++)
    {
        __m128i cx;
        __m128i cx1; 
        __m128i ax0 = _mm_set_epi64x(ah0, al0);
        __m128i ax1 = _mm_set_epi64x(ah1, al1);
        ptr0 = state_index(l0[idx0 & 0x1FFFF0]);
        ptr1 = state_index(l1[idx1 & 0x1FFFF0]);
        cx = _mm_load_si128((__m128i *) &l0[idx0 & 0x1FFFF0]);
        cx1 = _mm_load_si128((__m128i *) &l1[idx1 & 0x1FFFF0]);
        cx= SOFT_AES?soft_aesenc(cx, ax0):_mm_aesenc_si128(cx, ax0); 
        cx1= SOFT_AES?soft_aesenc(cx1, ax1):_mm_aesenc_si128(cx1, ax1); 

        _mm_store_si128(R128(ca), cx);  
        _mm_store_si128(R128(cb), cx1);  
        _mm_store_si128(R128(ca1), _mm_load_si128(R128(ptr0))); 
        _mm_store_si128(R128(cb1), _mm_load_si128(R128(ptr1))); 
        ptr0 = state_index(ca); 
        ptr1 = state_index(cb); 
        ca[0] ^= al0; ca[1] ^= ah0; 
        cb[0] ^= al1; cb[1] ^= ah1; 
        _mm_store_si128((__m128i *)ptr0,_mm_load_si128(R128(ca))); 
        _mm_store_si128((__m128i *)ptr1,_mm_load_si128(R128(cb))); 
        ptr0 = state_index(ca);
        ptr1 = state_index(cb);
        _mm_store_si128((__m128i *)ptr0, _mm_load_si128(R128(ca1)));
        _mm_store_si128((__m128i *)ptr1, _mm_load_si128(R128(cb1))); 
        ca1[0] ^= ca[0]; ca1[1] ^= ca[1];
        cb1[0] ^= cb[0]; cb1[1] ^= cb[1];
        ptr0 = state_index(ca1);
        ptr1 = state_index(cb1);
        _mm_store_si128((__m128i *)ptr0, _mm_load_si128(R128(ca1))); 
        _mm_store_si128((__m128i *)ptr1, _mm_load_si128(R128(cb1))); 
        uint64_t cl0, ch0;
        uint64_t cl1, ch1;
        cl0 = ((uint64_t*)ptr0)[0];  
        cl1 = ((uint64_t*)ptr1)[0]; 
        ch0 = ((uint64_t*)ptr0)[1];
        ch1 = ((uint64_t*)ptr1)[1];
        ((uint64_t*)ptr0)[0] = al0; 
        ((uint64_t*)ptr1)[0] = al1; 
        ((uint64_t*)ptr0)[1] = ah0; 
        ((uint64_t*)ptr1)[1] = ah1; 
        al0 ^= cl0;  
        al1 ^= cl1; 
        ah0 ^= ch0; 
        ah1 ^= ch1; 
        ax0 = _mm_set_epi64x(ah0, al0); 
        ax1 = _mm_set_epi64x(ah1, al1); 
        idx0 = al0;
        idx1 = al1;
    }
    cn_implode_scratchpad<ALGO, 2097152, SOFT_AES>((__m128i*) l0, (__m128i*) ctx[0]->state);
    cn_implode_scratchpad<ALGO, 2097152, SOFT_AES>((__m128i*) l1, (__m128i*) ctx[1]->state);

    xmrig::keccakf(h0, 24);
    xmrig::keccakf(h1, 24);
    extra_hashes[ctx[0]->state[0] & 3](ctx[0]->state, 200, output);
    extra_hashes[ctx[1]->state[0] & 3](ctx[1]->state, 200, output+32);
}	


#define CN_STEP1(a, b0, b1, c, l, ptr, idx)           \
    ptr = reinterpret_cast<__m128i*>(&l[idx & MASK]); \
    c = _mm_load_si128(ptr);


#define CN_STEP2(a, b0, b1, c, l, ptr, idx)                            \
    if (VARIANT == xmrig::VARIANT_TUBE) {                              \
        c = aes_round_tweak_div(c, a);                                 \
    }                                                                  \
    else if (SOFT_AES) {                                               \
        c = soft_aesenc(c, a);                                         \
    } else {                                                           \
        c = _mm_aesenc_si128(c, a);                                    \
    }                                                                  \
                                                                       \
    if (IS_V1 || (VARIANT == xmrig::VARIANT_2)) {                      \
        cryptonight_monero_tweak<VARIANT>((uint64_t*)ptr, l, idx & MASK, a, b0, b1, c); \
    } else {                                                           \
        _mm_store_si128(ptr, _mm_xor_si128(b0, c));                    \
    }


#define CN_STEP3(part, a, b0, b1, c, l, ptr, idx)     \
    idx = _mm_cvtsi128_si64(c);                       \
    ptr = reinterpret_cast<__m128i*>(&l[idx & MASK]); \
    uint64_t cl##part = ((uint64_t*)ptr)[0];          \
    uint64_t ch##part = ((uint64_t*)ptr)[1];


#define CN_STEP4(part, a, b0, b1, c, l, mc, ptr, idx)   \
    if (VARIANT == xmrig::VARIANT_2) {                  \
        VARIANT2_INTEGER_MATH(part, cl##part, c);       \
        lo = __umul128(idx, cl##part, &hi);             \
        VARIANT2_SHUFFLE2(l, idx & MASK, a, b0, b1, hi, lo); \
    } else {                                            \
        lo = __umul128(idx, cl##part, &hi);             \
    }                                                   \
    a = _mm_add_epi64(a, _mm_set_epi64x(lo, hi));       \
                                                        \
    if (IS_V1) {                                        \
        _mm_store_si128(ptr, _mm_xor_si128(a, mc));     \
                                                        \
        if (VARIANT == xmrig::VARIANT_TUBE ||           \
            VARIANT == xmrig::VARIANT_RTO) {            \
            ((uint64_t*)ptr)[1] ^= ((uint64_t*)ptr)[0]; \
        }                                               \
    } else {                                            \
        _mm_store_si128(ptr, a);                        \
    }                                                   \
                                                        \
    a = _mm_xor_si128(a, _mm_set_epi64x(ch##part, cl##part)); \
    idx = _mm_cvtsi128_si64(a);                         \
                                                        \
    if (ALGO == xmrig::CRYPTONIGHT_HEAVY) {             \
        int64_t n = ((int64_t*)&l[idx & MASK])[0];      \
        int32_t d = ((int32_t*)&l[idx & MASK])[2];      \
        int64_t q = n / (d | 0x5);                      \
        ((int64_t*)&l[idx & MASK])[0] = n ^ q;          \
        if (VARIANT == xmrig::VARIANT_XHV) {            \
            d = ~d;                                     \
        }                                               \
                                                        \
        idx = d ^ q;                                    \
    }                                                   \
    if (VARIANT == xmrig::VARIANT_2) {                  \
        b1 = b0;                                        \
    }                                                   \
    b0 = c;


#define CONST_INIT(ctx, n)                                                                       \
    __m128i mc##n;                                                                               \
    __m128i division_result_xmm_##n;                                                             \
    __m128i sqrt_result_xmm_##n;                                                                 \
    if (IS_V1) {                                                                                 \
        mc##n = _mm_set_epi64x(*reinterpret_cast<const uint64_t*>(input + n * size + 35) ^       \
                               *(reinterpret_cast<const uint64_t*>((ctx)->state) + 24), 0);      \
    }                                                                                            \
    if (VARIANT == xmrig::VARIANT_2) {                                                           \
        division_result_xmm_##n = _mm_cvtsi64_si128(h##n[12]);                                   \
        sqrt_result_xmm_##n = _mm_cvtsi64_si128(h##n[13]);                                       \
    }                                                                                            \
    __m128i ax##n = _mm_set_epi64x(h##n[1] ^ h##n[5], h##n[0] ^ h##n[4]);                        \
    __m128i bx##n##0 = _mm_set_epi64x(h##n[3] ^ h##n[7], h##n[2] ^ h##n[6]);                     \
    __m128i bx##n##1 = _mm_set_epi64x(h##n[9] ^ h##n[11], h##n[8] ^ h##n[10]);                   \
    __m128i cx##n = _mm_setzero_si128();


template<xmrig::Algo ALGO, bool SOFT_AES, xmrig::Variant VARIANT>
inline void cryptonight_triple_hash(const uint8_t *__restrict__ input, size_t size, uint8_t *__restrict__ output, cryptonight_ctx **__restrict__ ctx)
{
    xmrig::keccak(input       , size, ctx[0]->state);
    xmrig::keccak(input+  size, size, ctx[1]->state);
    xmrig::keccak(input+2*size, size, ctx[2]->state);

    cn_explode_scratchpad<ALGO, 2097152, SOFT_AES>((__m128i*) ctx[0]->state, (__m128i*) ctx[0]->memory);
    cn_explode_scratchpad<ALGO, 2097152, SOFT_AES>((__m128i*) ctx[1]->state, (__m128i*) ctx[1]->memory);
    cn_explode_scratchpad<ALGO, 2097152, SOFT_AES>((__m128i*) ctx[2]->state, (__m128i*) ctx[2]->memory);

    const uint8_t* l0 = ctx[0]->memory;
    const uint8_t* l1 = ctx[1]->memory;
    const uint8_t* l2 = ctx[2]->memory;
    uint64_t* h0 = reinterpret_cast<uint64_t*>(ctx[0]->state);
    uint64_t* h1 = reinterpret_cast<uint64_t*>(ctx[1]->state);
    uint64_t* h2 = reinterpret_cast<uint64_t*>(ctx[2]->state);

    uint64_t ca[2], ca1[2]; 
    uint64_t cb[2], cb1[2]; 
    uint64_t cc[2], cc1[2]; 
    uint64_t al0 = h0[0] ^ h0[4];
    uint64_t ah0 = h0[1] ^ h0[5];
    uint64_t al1 = h1[0] ^ h1[4];
    uint64_t ah1 = h1[1] ^ h1[5];
    uint64_t al2 = h2[0] ^ h2[4];
    uint64_t ah2 = h2[1] ^ h2[5];

    uint64_t idx0 = al0;
    uint64_t idx1 = al1;
    uint64_t idx2 = al2;
    size_t ptr0;
    size_t ptr1;
    size_t ptr2;

    for(size_t i = 0; i < 0x200000; i++)
    {
        __m128i cx;
        __m128i cx1; 
        __m128i cx2; 
        __m128i ax0 = _mm_set_epi64x(ah0, al0);
        __m128i ax1 = _mm_set_epi64x(ah1, al1);
        __m128i ax2 = _mm_set_epi64x(ah2, al2);
        ptr0 = state_index(l0[idx0 & 0x1FFFF0]);
        ptr1 = state_index(l1[idx1 & 0x1FFFF0]);
        ptr2 = state_index(l2[idx2 & 0x1FFFF0]);
        cx  = _mm_load_si128((__m128i *)  &l0[idx0 & 0x1FFFF0]);
        cx1 = _mm_load_si128((__m128i *)  &l1[idx1 & 0x1FFFF0]);
        cx2 = _mm_load_si128((__m128i *)  &l2[idx2 & 0x1FFFF0]);
        cx  = SOFT_AES?soft_aesenc(cx,  ax0):_mm_aesenc_si128(cx,  ax0); 
        cx1 = SOFT_AES?soft_aesenc(cx1, ax1):_mm_aesenc_si128(cx1, ax1); 
        cx2 = SOFT_AES?soft_aesenc(cx2, ax2):_mm_aesenc_si128(cx2, ax2); 

        _mm_store_si128(R128(ca), cx);  
        _mm_store_si128(R128(cb), cx1);  
        _mm_store_si128(R128(cc), cx2);  
        _mm_store_si128(R128(ca1), _mm_load_si128(R128(ptr0))); 
        _mm_store_si128(R128(cb1), _mm_load_si128(R128(ptr1))); 
        _mm_store_si128(R128(cc1), _mm_load_si128(R128(ptr2))); 
        ptr0 = state_index(ca); 
        ptr1 = state_index(cb); 
        ptr2 = state_index(cc); 
        ca[0] ^= al0; ca[1] ^= ah0; 
        cb[0] ^= al1; cb[1] ^= ah1; 
        cc[0] ^= al2; cc[1] ^= ah2; 
        _mm_store_si128((__m128i *)ptr0,_mm_load_si128(R128(ca))); 
        _mm_store_si128((__m128i *)ptr1,_mm_load_si128(R128(cb))); 
        _mm_store_si128((__m128i *)ptr2,_mm_load_si128(R128(cc))); 
        ptr0 = state_index(ca);
        ptr1 = state_index(cb);
        ptr2 = state_index(cc);
        _mm_store_si128((__m128i *)ptr0, _mm_load_si128(R128(ca1)));
        _mm_store_si128((__m128i *)ptr1, _mm_load_si128(R128(cb1))); 
        _mm_store_si128((__m128i *)ptr2, _mm_load_si128(R128(cc1))); 
        ca1[0] ^= ca[0]; ca1[1] ^= ca[1];
        cb1[0] ^= cb[0]; cb1[1] ^= cb[1];
        cc1[0] ^= cc[0]; cc1[1] ^= cc[1];
        ptr0 = state_index(ca1);
        ptr1 = state_index(cb1);
        ptr2 = state_index(cc1);
        _mm_store_si128((__m128i *)ptr0, _mm_load_si128(R128(ca1))); 
        _mm_store_si128((__m128i *)ptr1, _mm_load_si128(R128(cb1))); 
        _mm_store_si128((__m128i *)ptr2, _mm_load_si128(R128(cc1))); 
        uint64_t cl0, ch0;
        uint64_t cl1, ch1;
        uint64_t cl2, ch2;
        cl0 = ((uint64_t*)ptr0)[0];  
        cl1 = ((uint64_t*)ptr1)[0];  
        cl2 = ((uint64_t*)ptr2)[0]; 
        ch0 = ((uint64_t*)ptr0)[1];
        ch1 = ((uint64_t*)ptr1)[1];
        ch2 = ((uint64_t*)ptr2)[1];
        ((uint64_t*)ptr0)[0] = al0; 
        ((uint64_t*)ptr1)[0] = al1; 
        ((uint64_t*)ptr2)[0] = al2; 
        ((uint64_t*)ptr0)[1] = ah0; 
        ((uint64_t*)ptr1)[1] = ah1; 
        ((uint64_t*)ptr2)[1] = ah2; 
        al0 ^= cl0;  
        al1 ^= cl1; 
        al2 ^= cl2; 
        ah0 ^= ch0; 
        ah1 ^= ch1; 
        ah2 ^= ch2; 
        ax0 = _mm_set_epi64x(ah0, al0); 
        ax1 = _mm_set_epi64x(ah1, al1);
        ax2 = _mm_set_epi64x(ah2, al2); 
        idx0 = al0;
        idx1 = al1;
        idx2 = al2;
    }
    cn_implode_scratchpad<ALGO, 2097152, SOFT_AES>((__m128i*) l0, (__m128i*) ctx[0]->state);
    cn_implode_scratchpad<ALGO, 2097152, SOFT_AES>((__m128i*) l1, (__m128i*) ctx[1]->state);
    cn_implode_scratchpad<ALGO, 2097152, SOFT_AES>((__m128i*) l2, (__m128i*) ctx[2]->state);

    xmrig::keccakf(h0, 24);
    xmrig::keccakf(h1, 24);
    xmrig::keccakf(h2, 24);
    extra_hashes[ctx[0]->state[0] & 3](ctx[0]->state, 200, output);
    extra_hashes[ctx[1]->state[0] & 3](ctx[1]->state, 200, output+32);
    extra_hashes[ctx[2]->state[0] & 3](ctx[2]->state, 200, output+64);
}


template<xmrig::Algo ALGO, bool SOFT_AES, xmrig::Variant VARIANT>
inline void cryptonight_quad_hash(const uint8_t *__restrict__ input, size_t size, uint8_t *__restrict__ output, cryptonight_ctx **__restrict__ ctx)
{
    xmrig::keccak(input       , size, ctx[0]->state);
    xmrig::keccak(input+  size, size, ctx[1]->state);
    xmrig::keccak(input+2*size, size, ctx[2]->state);
    xmrig::keccak(input+3*size, size, ctx[3]->state);

    cn_explode_scratchpad<ALGO, 2097152, SOFT_AES>((__m128i*) ctx[0]->state, (__m128i*) ctx[0]->memory);
    cn_explode_scratchpad<ALGO, 2097152, SOFT_AES>((__m128i*) ctx[1]->state, (__m128i*) ctx[1]->memory);
    cn_explode_scratchpad<ALGO, 2097152, SOFT_AES>((__m128i*) ctx[2]->state, (__m128i*) ctx[2]->memory);
    cn_explode_scratchpad<ALGO, 2097152, SOFT_AES>((__m128i*) ctx[3]->state, (__m128i*) ctx[3]->memory);

    const uint8_t* l0 = ctx[0]->memory;
    const uint8_t* l1 = ctx[1]->memory;
    const uint8_t* l2 = ctx[2]->memory;
    const uint8_t* l3 = ctx[3]->memory;
    uint64_t* h0 = reinterpret_cast<uint64_t*>(ctx[0]->state);
    uint64_t* h1 = reinterpret_cast<uint64_t*>(ctx[1]->state);
    uint64_t* h2 = reinterpret_cast<uint64_t*>(ctx[2]->state);
    uint64_t* h3 = reinterpret_cast<uint64_t*>(ctx[3]->state);

    uint64_t ca[2], ca1[2]; 
    uint64_t cb[2], cb1[2]; 
    uint64_t cc[2], cc1[2]; 
    uint64_t cd[2], cd1[2]; 
    uint64_t al0 = h0[0] ^ h0[4];
    uint64_t ah0 = h0[1] ^ h0[5];
    uint64_t al1 = h1[0] ^ h1[4];
    uint64_t ah1 = h1[1] ^ h1[5];
    uint64_t al2 = h2[0] ^ h2[4];
    uint64_t ah2 = h2[1] ^ h2[5];
    uint64_t al3 = h3[0] ^ h3[4];
    uint64_t ah3 = h3[1] ^ h3[5];

    uint64_t idx0 = al0;
    uint64_t idx1 = al1;
    uint64_t idx2 = al2;
    uint64_t idx3 = al3;
    size_t ptr0;
    size_t ptr1;
    size_t ptr2;
    size_t ptr3;

    for(size_t i = 0; i < 0x200000; i++)
    {
        __m128i cx;
        __m128i cx1; 
        __m128i cx2; 
        __m128i cx3; 
        __m128i ax0 = _mm_set_epi64x(ah0, al0);
        __m128i ax1 = _mm_set_epi64x(ah1, al1);
        __m128i ax2 = _mm_set_epi64x(ah2, al2);
        __m128i ax3 = _mm_set_epi64x(ah3, al3);
        ptr0 = state_index(l0[idx0 & 0x1FFFF0]);
        ptr1 = state_index(l1[idx1 & 0x1FFFF0]);
        ptr2 = state_index(l2[idx2 & 0x1FFFF0]);
        ptr3 = state_index(l3[idx3 & 0x1FFFF0]);
        cx  = _mm_load_si128((__m128i *) &l0[idx0 & 0x1FFFF0]);
        cx1 = _mm_load_si128((__m128i *) &l1[idx1 & 0x1FFFF0]);
        cx2 = _mm_load_si128((__m128i *) &l2[idx2 & 0x1FFFF0]);
        cx3 = _mm_load_si128((__m128i *) &l3[idx3 & 0x1FFFF0]);
        cx  = SOFT_AES?soft_aesenc(cx,  ax0):_mm_aesenc_si128(cx,  ax0); 
        cx1 = SOFT_AES?soft_aesenc(cx1, ax1):_mm_aesenc_si128(cx1, ax1); 
        cx2 = SOFT_AES?soft_aesenc(cx2, ax2):_mm_aesenc_si128(cx2, ax2); 
        cx3 = SOFT_AES?soft_aesenc(cx3, ax3):_mm_aesenc_si128(cx3, ax3); 
        _mm_store_si128(R128(ca), cx);  
        _mm_store_si128(R128(cb), cx1);  
        _mm_store_si128(R128(cc), cx2);  
        _mm_store_si128(R128(cd), cx3);  
        _mm_store_si128(R128(ca1), _mm_load_si128(R128(ptr0))); 
        _mm_store_si128(R128(cb1), _mm_load_si128(R128(ptr1))); 
        _mm_store_si128(R128(cc1), _mm_load_si128(R128(ptr2))); 
        _mm_store_si128(R128(cd1), _mm_load_si128(R128(ptr3))); 
        ptr0 = state_index(ca); 
        ptr1 = state_index(cb); 
        ptr2 = state_index(cc); 
        ptr3 = state_index(cd); 
        ca[0] ^= al0; ca[1] ^= ah0; 
        cb[0] ^= al1; cb[1] ^= ah1; 
        cc[0] ^= al2; cc[1] ^= ah2; 
        cd[0] ^= al3; cd[1] ^= ah3; 
        _mm_store_si128((__m128i *)ptr0,_mm_load_si128(R128(ca))); 
        _mm_store_si128((__m128i *)ptr1,_mm_load_si128(R128(cb))); 
        _mm_store_si128((__m128i *)ptr2,_mm_load_si128(R128(cc))); 
        _mm_store_si128((__m128i *)ptr3,_mm_load_si128(R128(cd))); 
        ptr0 = state_index(ca);
        ptr1 = state_index(cb);
        ptr2 = state_index(cc);
        ptr3 = state_index(cd);
        _mm_store_si128((__m128i *)ptr0, _mm_load_si128(R128(ca1)));
        _mm_store_si128((__m128i *)ptr1, _mm_load_si128(R128(cb1))); 
        _mm_store_si128((__m128i *)ptr2, _mm_load_si128(R128(cc1))); 
        _mm_store_si128((__m128i *)ptr3, _mm_load_si128(R128(cd1))); 
        ca1[0] ^= ca[0]; ca1[1] ^= ca[1];
        cb1[0] ^= cb[0]; cb1[1] ^= cb[1];
        cc1[0] ^= cc[0]; cc1[1] ^= cc[1];
        cd1[0] ^= cd[0]; cd1[1] ^= cd[1];
        ptr0 = state_index(ca1);
        ptr1 = state_index(cb1);
        ptr2 = state_index(cc1);
        ptr3 = state_index(cd1);
        _mm_store_si128((__m128i *)ptr0, _mm_load_si128(R128(ca1))); 
        _mm_store_si128((__m128i *)ptr1, _mm_load_si128(R128(cb1))); 
        _mm_store_si128((__m128i *)ptr2, _mm_load_si128(R128(cb1))); 
        _mm_store_si128((__m128i *)ptr3, _mm_load_si128(R128(cb1))); 
        uint64_t cl0, ch0;
        uint64_t cl1, ch1;
        uint64_t cl2, ch2;
        uint64_t cl3, ch3;
        cl0 = ((uint64_t*)ptr0)[0];  
        cl1 = ((uint64_t*)ptr1)[0];  
        cl2 = ((uint64_t*)ptr2)[0];  
        cl3 = ((uint64_t*)ptr3)[0]; 
        ch0 = ((uint64_t*)ptr0)[1];
        ch1 = ((uint64_t*)ptr1)[1];
        ch2 = ((uint64_t*)ptr2)[1];
        ch3 = ((uint64_t*)ptr3)[1];
        ((uint64_t*)ptr0)[0] = al0; 
        ((uint64_t*)ptr1)[0] = al1; 
        ((uint64_t*)ptr2)[0] = al2; 
        ((uint64_t*)ptr3)[0] = al3; 
        ((uint64_t*)ptr0)[1] = ah0; 
        ((uint64_t*)ptr1)[1] = ah1; 
        ((uint64_t*)ptr2)[1] = ah2; 
        ((uint64_t*)ptr3)[1] = ah3; 
        al0 ^= cl0;  
        al1 ^= cl1; 
        al2 ^= cl2; 
        al3 ^= cl3; 
        ah0 ^= ch0; 
        ah1 ^= ch1; 
        ah2 ^= ch2; 
        ah3 ^= ch3; 
        ax0 = _mm_set_epi64x(ah0, al0); 
        ax1 = _mm_set_epi64x(ah1, al1);
        ax2 = _mm_set_epi64x(ah2, al2); 
        ax3 = _mm_set_epi64x(ah3, al3); 
        idx0 = al0;
        idx1 = al1;
        idx2 = al2;
        idx3 = al3;
    }
    cn_implode_scratchpad<ALGO, 2097152, SOFT_AES>((__m128i*) l0, (__m128i*) ctx[0]->state);
    cn_implode_scratchpad<ALGO, 2097152, SOFT_AES>((__m128i*) l1, (__m128i*) ctx[1]->state);
    cn_implode_scratchpad<ALGO, 2097152, SOFT_AES>((__m128i*) l2, (__m128i*) ctx[2]->state);
    cn_implode_scratchpad<ALGO, 2097152, SOFT_AES>((__m128i*) l3, (__m128i*) ctx[3]->state);

    xmrig::keccakf(h0, 24);
    xmrig::keccakf(h1, 24);
    xmrig::keccakf(h2, 24);
    xmrig::keccakf(h3, 24);
    extra_hashes[ctx[0]->state[0] & 3](ctx[0]->state, 200, output);
    extra_hashes[ctx[1]->state[0] & 3](ctx[1]->state, 200, output+32);
    extra_hashes[ctx[2]->state[0] & 3](ctx[2]->state, 200, output+64);
    extra_hashes[ctx[3]->state[0] & 3](ctx[3]->state, 200, output+96);
}


template<xmrig::Algo ALGO, bool SOFT_AES, xmrig::Variant VARIANT>
inline void cryptonight_penta_hash(const uint8_t *__restrict__ input, size_t size, uint8_t *__restrict__ output, cryptonight_ctx **__restrict__ ctx)
{
    xmrig::keccak(input       , size, ctx[0]->state);
    xmrig::keccak(input+  size, size, ctx[1]->state);
    xmrig::keccak(input+2*size, size, ctx[2]->state);
    xmrig::keccak(input+3*size, size, ctx[3]->state);
    xmrig::keccak(input+4*size, size, ctx[4]->state);

    cn_explode_scratchpad<ALGO, 2097152, SOFT_AES>((__m128i*) ctx[0]->state, (__m128i*) ctx[0]->memory);
    cn_explode_scratchpad<ALGO, 2097152, SOFT_AES>((__m128i*) ctx[1]->state, (__m128i*) ctx[1]->memory);
    cn_explode_scratchpad<ALGO, 2097152, SOFT_AES>((__m128i*) ctx[2]->state, (__m128i*) ctx[2]->memory);
    cn_explode_scratchpad<ALGO, 2097152, SOFT_AES>((__m128i*) ctx[3]->state, (__m128i*) ctx[3]->memory);
    cn_explode_scratchpad<ALGO, 2097152, SOFT_AES>((__m128i*) ctx[4]->state, (__m128i*) ctx[4]->memory);

    const uint8_t* l0 = ctx[0]->memory;
    const uint8_t* l1 = ctx[1]->memory;
    const uint8_t* l2 = ctx[2]->memory;
    const uint8_t* l3 = ctx[3]->memory;
    const uint8_t* l4 = ctx[3]->memory;
    uint64_t* h0 = reinterpret_cast<uint64_t*>(ctx[0]->state);
    uint64_t* h1 = reinterpret_cast<uint64_t*>(ctx[1]->state);
    uint64_t* h2 = reinterpret_cast<uint64_t*>(ctx[2]->state);
    uint64_t* h3 = reinterpret_cast<uint64_t*>(ctx[3]->state);
    uint64_t* h4 = reinterpret_cast<uint64_t*>(ctx[3]->state);

    uint64_t ca[2], ca1[2]; 
    uint64_t cb[2], cb1[2]; 
    uint64_t cc[2], cc1[2]; 
    uint64_t cd[2], cd1[2]; 
    uint64_t ce[2], ce1[2]; 
    uint64_t al0 = h0[0] ^ h0[4];
    uint64_t ah0 = h0[1] ^ h0[5];
    uint64_t al1 = h1[0] ^ h1[4];
    uint64_t ah1 = h1[1] ^ h1[5];
    uint64_t al2 = h2[0] ^ h2[4];
    uint64_t ah2 = h2[1] ^ h2[5];
    uint64_t al3 = h3[0] ^ h3[4];
    uint64_t ah3 = h3[1] ^ h3[5];
    uint64_t al4 = h4[0] ^ h4[4];
    uint64_t ah4 = h4[1] ^ h4[5];

    uint64_t idx0 = al0;
    uint64_t idx1 = al1;
    uint64_t idx2 = al2;
    uint64_t idx3 = al3;
    uint64_t idx4 = al4;
    size_t ptr0;
    size_t ptr1;
    size_t ptr2;
    size_t ptr3;
    size_t ptr4;

    for(size_t i = 0; i < 0x200000; i++)
    {
        __m128i cx;
        __m128i cx1; 
        __m128i cx2; 
        __m128i cx3; 
        __m128i cx4; 
        __m128i ax0 = _mm_set_epi64x(ah0, al0);
        __m128i ax1 = _mm_set_epi64x(ah1, al1);
        __m128i ax2 = _mm_set_epi64x(ah2, al2);
        __m128i ax3 = _mm_set_epi64x(ah3, al3);
        __m128i ax4 = _mm_set_epi64x(ah4, al4);
        ptr0 = state_index(l0[idx0 & 0x1FFFF0]);
        ptr1 = state_index(l1[idx1 & 0x1FFFF0]);
        ptr2 = state_index(l2[idx2 & 0x1FFFF0]);
        ptr3 = state_index(l3[idx3 & 0x1FFFF0]);
        ptr4 = state_index(l4[idx4 & 0x1FFFF0]);
        cx  = _mm_load_si128((__m128i *) &l0[idx0 & 0x1FFFF0]);
        cx1 = _mm_load_si128((__m128i *) &l1[idx1 & 0x1FFFF0]);
        cx2 = _mm_load_si128((__m128i *) &l2[idx2 & 0x1FFFF0]);
        cx3 = _mm_load_si128((__m128i *) &l3[idx3 & 0x1FFFF0]);
        cx4 = _mm_load_si128((__m128i *) &l4[idx4 & 0x1FFFF0]);
        cx  = SOFT_AES?soft_aesenc(cx,  ax0):_mm_aesenc_si128(cx,  ax0); 
        cx1 = SOFT_AES?soft_aesenc(cx1, ax1):_mm_aesenc_si128(cx1, ax1); 
        cx2 = SOFT_AES?soft_aesenc(cx2, ax2):_mm_aesenc_si128(cx2, ax2); 
        cx3 = SOFT_AES?soft_aesenc(cx3, ax3):_mm_aesenc_si128(cx3, ax3); 
        cx4 = SOFT_AES?soft_aesenc(cx4, ax4):_mm_aesenc_si128(cx4, ax4); 
        _mm_store_si128(R128(ca), cx);  
        _mm_store_si128(R128(cb), cx1);  
        _mm_store_si128(R128(cc), cx2);  
        _mm_store_si128(R128(cd), cx3);  
        _mm_store_si128(R128(ce), cx4);  
        _mm_store_si128(R128(ca1), _mm_load_si128(R128(ptr0))); 
        _mm_store_si128(R128(cb1), _mm_load_si128(R128(ptr1))); 
        _mm_store_si128(R128(cc1), _mm_load_si128(R128(ptr2))); 
        _mm_store_si128(R128(cd1), _mm_load_si128(R128(ptr3))); 
        _mm_store_si128(R128(ce1), _mm_load_si128(R128(ptr4))); 
        ptr0 = state_index(ca); 
        ptr1 = state_index(cb); 
        ptr2 = state_index(cc); 
        ptr3 = state_index(cd); 
        ptr3 = state_index(ce); 
        ca[0] ^= al0; ca[1] ^= ah0; 
        cb[0] ^= al1; cb[1] ^= ah1; 
        cc[0] ^= al2; cc[1] ^= ah2; 
        cd[0] ^= al3; cd[1] ^= ah3; 
        ce[0] ^= al4; cd[1] ^= ah4; 
        _mm_store_si128((__m128i *)ptr0,_mm_load_si128(R128(ca))); 
        _mm_store_si128((__m128i *)ptr1,_mm_load_si128(R128(cb))); 
        _mm_store_si128((__m128i *)ptr2,_mm_load_si128(R128(cc))); 
        _mm_store_si128((__m128i *)ptr3,_mm_load_si128(R128(cd))); 
        _mm_store_si128((__m128i *)ptr4,_mm_load_si128(R128(ce))); 
        ptr0 = state_index(ca);
        ptr1 = state_index(cb);
        ptr2 = state_index(cc);
        ptr3 = state_index(cd);
        ptr4 = state_index(ce);
        _mm_store_si128((__m128i *)ptr0, _mm_load_si128(R128(ca1)));
        _mm_store_si128((__m128i *)ptr1, _mm_load_si128(R128(cb1))); 
        _mm_store_si128((__m128i *)ptr2, _mm_load_si128(R128(cc1))); 
        _mm_store_si128((__m128i *)ptr3, _mm_load_si128(R128(cd1))); 
        _mm_store_si128((__m128i *)ptr4, _mm_load_si128(R128(ce1))); 
        ca1[0] ^= ca[0]; ca1[1] ^= ca[1];
        cb1[0] ^= cb[0]; cb1[1] ^= cb[1];
        cc1[0] ^= cc[0]; cc1[1] ^= cc[1];
        cd1[0] ^= cd[0]; cd1[1] ^= cd[1];
        ce1[0] ^= ce[0]; ce1[1] ^= ce[1];
        ptr0 = state_index(ca1);
        ptr1 = state_index(cb1);
        ptr2 = state_index(cb1);
        ptr3 = state_index(cb1);
        ptr4 = state_index(cb1);
        _mm_store_si128((__m128i *)ptr0, _mm_load_si128(R128(ca1))); 
        _mm_store_si128((__m128i *)ptr1, _mm_load_si128(R128(cb1))); 
        _mm_store_si128((__m128i *)ptr2, _mm_load_si128(R128(cb1))); 
        _mm_store_si128((__m128i *)ptr3, _mm_load_si128(R128(cb1))); 
        _mm_store_si128((__m128i *)ptr4, _mm_load_si128(R128(cb1))); 
        uint64_t cl0, ch0;
        uint64_t cl1, ch1;
        uint64_t cl2, ch2;
        uint64_t cl3, ch3;
        uint64_t cl4, ch4;
        cl0 = ((uint64_t*)ptr0)[0];  
        cl1 = ((uint64_t*)ptr1)[0];  
        cl2 = ((uint64_t*)ptr2)[0];  
        cl3 = ((uint64_t*)ptr3)[0];  
        cl4 = ((uint64_t*)ptr4)[0]; 
        ch0 = ((uint64_t*)ptr0)[1];
        ch1 = ((uint64_t*)ptr1)[1];
        ch2 = ((uint64_t*)ptr2)[1];
        ch3 = ((uint64_t*)ptr3)[1];
        ch4 = ((uint64_t*)ptr4)[1];
        ((uint64_t*)ptr0)[0] = al0; 
        ((uint64_t*)ptr1)[0] = al1; 
        ((uint64_t*)ptr2)[0] = al2; 
        ((uint64_t*)ptr3)[0] = al3; 
        ((uint64_t*)ptr4)[0] = al4; 
        ((uint64_t*)ptr0)[1] = ah0; 
        ((uint64_t*)ptr1)[1] = ah1; 
        ((uint64_t*)ptr2)[1] = ah2; 
        ((uint64_t*)ptr3)[1] = ah3; 
        ((uint64_t*)ptr4)[1] = ah4; 
        al0 ^= cl0;  
        al1 ^= cl1; 
        al2 ^= cl2; 
        al3 ^= cl3; 
        al4 ^= cl4; 
        ah0 ^= ch0; 
        ah1 ^= ch1; 
        ah2 ^= ch2; 
        ah3 ^= ch3; 
        ah4 ^= ch4; 
        ax0 = _mm_set_epi64x(ah0, al0); 
        ax1 = _mm_set_epi64x(ah1, al1);
        ax2 = _mm_set_epi64x(ah2, al2); 
        ax3 = _mm_set_epi64x(ah3, al3); 
        ax4 = _mm_set_epi64x(ah4, al4); 
        idx0 = al0;
        idx1 = al1;
        idx2 = al2;
        idx3 = al3;
        idx4 = al4;
    }
    cn_implode_scratchpad<ALGO, 2097152, SOFT_AES>((__m128i*) l0, (__m128i*) ctx[0]->state);
    cn_implode_scratchpad<ALGO, 2097152, SOFT_AES>((__m128i*) l1, (__m128i*) ctx[1]->state);
    cn_implode_scratchpad<ALGO, 2097152, SOFT_AES>((__m128i*) l2, (__m128i*) ctx[2]->state);
    cn_implode_scratchpad<ALGO, 2097152, SOFT_AES>((__m128i*) l3, (__m128i*) ctx[3]->state);
    cn_implode_scratchpad<ALGO, 2097152, SOFT_AES>((__m128i*) l4, (__m128i*) ctx[4]->state);

    xmrig::keccakf(h0, 24);
    xmrig::keccakf(h1, 24);
    xmrig::keccakf(h2, 24);
    xmrig::keccakf(h3, 24);
    xmrig::keccakf(h4, 24);
    extra_hashes[ctx[0]->state[0] & 3](ctx[0]->state, 200, output);
    extra_hashes[ctx[1]->state[0] & 3](ctx[1]->state, 200, output+32);
    extra_hashes[ctx[2]->state[0] & 3](ctx[2]->state, 200, output+64);
    extra_hashes[ctx[3]->state[0] & 3](ctx[3]->state, 200, output+96);
    extra_hashes[ctx[4]->state[0] & 3](ctx[4]->state, 200, output+128);
}

#endif /* XMRIG_CRYPTONIGHT_X86_H */
