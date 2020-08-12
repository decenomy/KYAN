// Copyright (c) 2013-2015 The Bitcoin Core developers
// Copyright (c) 2020-2020 The Kyan Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "hash.h"
#include "crypto/common.h"
#include "crypto/hmac_sha512.h"
#include "pubkey.h"

auto hBlake512 = [](const void *data, size_t len) {
    
    sph_blake512_context ctx_blake;
    uint512 hash;

    sph_blake512_init(&ctx_blake);
    sph_blake512 (&ctx_blake, data, len);
    sph_blake512_close(&ctx_blake, static_cast<void*>(&hash));

    return hash;
};

auto hBmw512 = [](const void *data, size_t len) {
    
    sph_bmw512_context ctx_bmw;
    uint512 hash;

    sph_bmw512_init(&ctx_bmw);
    sph_bmw512 (&ctx_bmw, data, len);
    sph_bmw512_close(&ctx_bmw, static_cast<void*>(&hash));

    return hash;
};

auto hGroestl512 = [](const void *data, size_t len) {
    
    sph_groestl512_context ctx_groestl;
    uint512 hash;

    sph_groestl512_init(&ctx_groestl);
    sph_groestl512 (&ctx_groestl, data, len);
    sph_groestl512_close(&ctx_groestl, static_cast<void*>(&hash));

    return hash;
};

auto hSkein512 = [](const void *data, size_t len) {
    
    sph_skein512_context ctx_skein;
    uint512 hash;

    sph_skein512_init(&ctx_skein);
    sph_skein512 (&ctx_skein, data, len);
    sph_skein512_close(&ctx_skein, static_cast<void*>(&hash));

    return hash;
};

auto hJh512 = [](const void *data, size_t len) {
    
    sph_jh512_context ctx_jh;
    uint512 hash;

    sph_jh512_init(&ctx_jh);
    sph_jh512 (&ctx_jh, data, len);
    sph_jh512_close(&ctx_jh, static_cast<void*>(&hash));

    return hash;
};

auto hKeccak512 = [](const void *data, size_t len) {
    
    sph_keccak512_context ctx_keccak;
    uint512 hash;

    sph_keccak512_init(&ctx_keccak);
    sph_keccak512 (&ctx_keccak, data, len);
    sph_keccak512_close(&ctx_keccak, static_cast<void*>(&hash));

    return hash;
};

auto hLuffa512 = [](const void *data, size_t len) {
    
    sph_luffa512_context ctx_luffa;
    uint512 hash;

    sph_luffa512_init(&ctx_luffa);
    sph_luffa512 (&ctx_luffa, data, len);
    sph_luffa512_close(&ctx_luffa, static_cast<void*>(&hash));

    return hash;
};

auto hCubehash512 = [](const void *data, size_t len) {
    
    sph_cubehash512_context ctx_cubehash;
    uint512 hash;

    sph_cubehash512_init(&ctx_cubehash);
    sph_cubehash512 (&ctx_cubehash, data, len);
    sph_cubehash512_close(&ctx_cubehash, static_cast<void*>(&hash));

    return hash;
};

auto hShavite512 = [](const void *data, size_t len) {
    
    sph_shavite512_context ctx_shavite;
    uint512 hash;

    sph_shavite512_init(&ctx_shavite);
    sph_shavite512 (&ctx_shavite, data, len);
    sph_shavite512_close(&ctx_shavite, static_cast<void*>(&hash));

    return hash;
};

auto hSimd512 = [](const void *data, size_t len) {
    
    sph_simd512_context ctx_simd;
    uint512 hash;

    sph_simd512_init(&ctx_simd);
    sph_simd512 (&ctx_simd, data, len);
    sph_simd512_close(&ctx_simd, static_cast<void*>(&hash));

    return hash;
};

auto hEcho512 = [](const void *data, size_t len) {
    
    sph_echo512_context ctx_echo;
    uint512 hash;

    sph_echo512_init(&ctx_echo);
    sph_echo512 (&ctx_echo, data, len);
    sph_echo512_close(&ctx_echo, static_cast<void*>(&hash));

    return hash;
};

std::function<uint512(const void *data, size_t len)> fnHashX11K[] = {
    hBlake512,
    hBmw512,
    hGroestl512,
    hSkein512,
    hJh512,
    hKeccak512,
    hLuffa512,
    hCubehash512,
    hShavite512,
    hSimd512,
    hEcho512
};

inline uint32_t ROTL32(uint32_t x, int8_t r)
{
    return (x << r) | (x >> (32 - r));
}

unsigned int MurmurHash3(unsigned int nHashSeed, const std::vector<unsigned char>& vDataToHash)
{
    // The following is MurmurHash3 (x86_32), see http://code.google.com/p/smhasher/source/browse/trunk/MurmurHash3.cpp
    uint32_t h1 = nHashSeed;
    const uint32_t c1 = 0xcc9e2d51;
    const uint32_t c2 = 0x1b873593;

    const int nblocks = vDataToHash.size() / 4;

    //----------
    // body
    const uint8_t* blocks = vDataToHash.data();

    for (int i = 0; i < nblocks; ++i) {
        uint32_t k1 = ReadLE32(blocks + i*4);

        k1 *= c1;
        k1 = ROTL32(k1, 15);
        k1 *= c2;

        h1 ^= k1;
        h1 = ROTL32(h1, 13);
        h1 = h1 * 5 + 0xe6546b64;
    }

    //----------
    // tail
    const uint8_t* tail = vDataToHash.data() + nblocks * 4;

    uint32_t k1 = 0;

    switch (vDataToHash.size() & 3) {
        case 3:
            k1 ^= tail[2] << 16;
        case 2:
            k1 ^= tail[1] << 8;
        case 1:
            k1 ^= tail[0];
            k1 *= c1;
            k1 = ROTL32(k1, 15);
            k1 *= c2;
            h1 ^= k1;
    }

    //----------
    // finalization
    h1 ^= vDataToHash.size();
    h1 ^= h1 >> 16;
    h1 *= 0x85ebca6b;
    h1 ^= h1 >> 13;
    h1 *= 0xc2b2ae35;
    h1 ^= h1 >> 16;

    return h1;
}

void BIP32Hash(const ChainCode &chainCode, unsigned int nChild, unsigned char header, const unsigned char data[32], unsigned char output[64])
{
    unsigned char num[4];
    num[0] = (nChild >> 24) & 0xFF;
    num[1] = (nChild >> 16) & 0xFF;
    num[2] = (nChild >>  8) & 0xFF;
    num[3] = (nChild >>  0) & 0xFF;
    CHMAC_SHA512(chainCode.begin(), chainCode.size()).Write(&header, 1).Write(data, 32).Write(num, 4).Finalize(output);
}

#define ROTL(x, b) (uint64_t)(((x) << (b)) | ((x) >> (64 - (b))))

#define SIPROUND do { \
    v0 += v1; v1 = ROTL(v1, 13); v1 ^= v0; \
    v0 = ROTL(v0, 32); \
    v2 += v3; v3 = ROTL(v3, 16); v3 ^= v2; \
    v0 += v3; v3 = ROTL(v3, 21); v3 ^= v0; \
    v2 += v1; v1 = ROTL(v1, 17); v1 ^= v2; \
    v2 = ROTL(v2, 32); \
} while (0)

CSipHasher::CSipHasher(uint64_t k0, uint64_t k1)
{
    v[0] = 0x736f6d6570736575ULL ^ k0;
    v[1] = 0x646f72616e646f6dULL ^ k1;
    v[2] = 0x6c7967656e657261ULL ^ k0;
    v[3] = 0x7465646279746573ULL ^ k1;
    count = 0;
    tmp = 0;
}

CSipHasher& CSipHasher::Write(uint64_t data)
{
    uint64_t v0 = v[0], v1 = v[1], v2 = v[2], v3 = v[3];

    assert(count % 8 == 0);

    v3 ^= data;
    SIPROUND;
    SIPROUND;
    v0 ^= data;

    v[0] = v0;
    v[1] = v1;
    v[2] = v2;
    v[3] = v3;

    count += 8;
    return *this;
}

CSipHasher& CSipHasher::Write(const unsigned char* data, size_t size)
{
    uint64_t v0 = v[0], v1 = v[1], v2 = v[2], v3 = v[3];
    uint64_t t = tmp;
    int c = count;

    while (size--) {
        t |= ((uint64_t)(*(data++))) << (8 * (c % 8));
        c++;
        if ((c & 7) == 0) {
            v3 ^= t;
            SIPROUND;
            SIPROUND;
            v0 ^= t;
            t = 0;
        }
    }

    v[0] = v0;
    v[1] = v1;
    v[2] = v2;
    v[3] = v3;
    count = c;
    tmp = t;

    return *this;
}

uint64_t CSipHasher::Finalize() const
{
    uint64_t v0 = v[0], v1 = v[1], v2 = v[2], v3 = v[3];

    uint64_t t = tmp | (((uint64_t)count) << 56);

    v3 ^= t;
    SIPROUND;
    SIPROUND;
    v0 ^= t;
    v2 ^= 0xFF;
    SIPROUND;
    SIPROUND;
    SIPROUND;
    SIPROUND;
    return v0 ^ v1 ^ v2 ^ v3;
}

uint64_t SipHashUint256(uint64_t k0, uint64_t k1, const uint256& val)
{
    /* Specialized implementation for efficiency */
    uint64_t d = val.GetUint64(0);

    uint64_t v0 = 0x736f6d6570736575ULL ^ k0;
    uint64_t v1 = 0x646f72616e646f6dULL ^ k1;
    uint64_t v2 = 0x6c7967656e657261ULL ^ k0;
    uint64_t v3 = 0x7465646279746573ULL ^ k1 ^ d;

    SIPROUND;
    SIPROUND;
    v0 ^= d;
    d = val.GetUint64(1);
    v3 ^= d;
    SIPROUND;
    SIPROUND;
    v0 ^= d;
    d = val.GetUint64(2);
    v3 ^= d;
    SIPROUND;
    SIPROUND;
    v0 ^= d;
    d = val.GetUint64(3);
    v3 ^= d;
    SIPROUND;
    SIPROUND;
    v0 ^= d;
    v3 ^= ((uint64_t)4) << 59;
    SIPROUND;
    SIPROUND;
    v0 ^= ((uint64_t)4) << 59;
    v2 ^= 0xFF;
    SIPROUND;
    SIPROUND;
    SIPROUND;
    SIPROUND;
    return v0 ^ v1 ^ v2 ^ v3;
}

uint64_t SipHashUint256Extra(uint64_t k0, uint64_t k1, const uint256& val, uint32_t extra)
{
    /* Specialized implementation for efficiency */
    uint64_t d = val.GetUint64(0);

    uint64_t v0 = 0x736f6d6570736575ULL ^ k0;
    uint64_t v1 = 0x646f72616e646f6dULL ^ k1;
    uint64_t v2 = 0x6c7967656e657261ULL ^ k0;
    uint64_t v3 = 0x7465646279746573ULL ^ k1 ^ d;

    SIPROUND;
    SIPROUND;
    v0 ^= d;
    d = val.GetUint64(1);
    v3 ^= d;
    SIPROUND;
    SIPROUND;
    v0 ^= d;
    d = val.GetUint64(2);
    v3 ^= d;
    SIPROUND;
    SIPROUND;
    v0 ^= d;
    d = val.GetUint64(3);
    v3 ^= d;
    SIPROUND;
    SIPROUND;
    v0 ^= d;
    d = (((uint64_t)36) << 56) | extra;
    v3 ^= d;
    SIPROUND;
    SIPROUND;
    v0 ^= d;
    v2 ^= 0xFF;
    SIPROUND;
    SIPROUND;
    SIPROUND;
    SIPROUND;
    return v0 ^ v1 ^ v2 ^ v3;
}
