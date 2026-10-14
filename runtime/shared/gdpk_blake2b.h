
#pragma once

#include <cstdint>
#include <cstring>
#include <cstddef>

namespace gdpk {

class Blake2b {
public:
	static constexpr size_t OUT_MAX = 64;
	static constexpr size_t BLOCK = 128;

	void init(size_t out_len, const uint8_t person[16] = nullptr,
			const uint8_t salt[16] = nullptr) {
		uint8_t p[64];
		memset(p, 0, sizeof(p));
		p[0] = (uint8_t)out_len; 
		p[1] = 0;                
		p[2] = 1;                
		p[3] = 1;                
		if (salt) memcpy(p + 32, salt, 16);
		if (person) memcpy(p + 48, person, 16);

		for (int i = 0; i < 8; i++)
			h[i] = IV[i] ^ load64(p + 8 * i);
		t[0] = t[1] = 0;
		f[0] = f[1] = 0;
		buflen = 0;
		outlen = out_len;
	}

	void update(const uint8_t *in, size_t inlen) {
		if (inlen == 0) return;
		size_t left = buflen;
		size_t fill = BLOCK - left;
		if (inlen > fill) {
			buflen = 0;
			memcpy(buf + left, in, fill);
			incr(BLOCK);
			compress(buf);
			in += fill;
			inlen -= fill;
			while (inlen > BLOCK) {
				incr(BLOCK);
				compress(in);
				in += BLOCK;
				inlen -= BLOCK;
			}
		}
		memcpy(buf + buflen, in, inlen);
		buflen += inlen;
	}

	void final(uint8_t *out) {
		uint8_t buffer[OUT_MAX];
		incr(buflen);
		f[0] = ~0ULL;
		memset(buf + buflen, 0, BLOCK - buflen);
		compress(buf);
		for (int i = 0; i < 8; i++) store64(buffer + 8 * i, h[i]);
		memcpy(out, buffer, outlen);
	}

	static void hash(const uint8_t *in, size_t inlen, uint8_t *out,
			size_t out_len, const uint8_t *person = nullptr,
			size_t person_len = 0) {
		uint8_t p16[16] = {0};
		if (person && person_len) {
			size_t n = person_len < 16 ? person_len : 16;
			memcpy(p16, person, n);
		}
		Blake2b b;
		b.init(out_len, person ? p16 : nullptr);
		b.update(in, inlen);
		b.final(out);
	}

	static void kdf(uint8_t out[32], const char *label,
			const uint8_t *const *parts, const size_t *part_lens, int nparts) {
		uint8_t p16[16] = {0};
		const char prefix[] = "gdprotect";
		memcpy(p16, prefix, 9);          
		size_t l = strlen(label);
		if (l > 6) l = 6;                
		memcpy(p16 + 10, label, l);
		Blake2b b;
		b.init(32, p16);
		for (int i = 0; i < nparts; i++) {
			uint8_t lenbuf[4] = {
				(uint8_t)(part_lens[i]), (uint8_t)(part_lens[i] >> 8),
				(uint8_t)(part_lens[i] >> 16), (uint8_t)(part_lens[i] >> 24)};
			b.update(lenbuf, 4);
			b.update(parts[i], part_lens[i]);
		}
		b.final(out);
	}

private:
	static constexpr uint64_t IV[8] = {
		0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
		0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
		0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
		0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL};

	static constexpr uint8_t SIGMA[12][16] = {
		{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
		{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
		{11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
		{7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
		{9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
		{2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
		{12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
		{13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
		{6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
		{10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
		{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
		{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3}};

	uint64_t h[8];
	uint64_t t[2];
	uint64_t f[2];
	uint8_t buf[BLOCK];
	size_t buflen = 0;
	size_t outlen = 0;

	static uint64_t load64(const uint8_t *p) {
		uint64_t w = 0;
		for (int i = 0; i < 8; i++) w |= (uint64_t)p[i] << (8 * i);
		return w;
	}
	static void store64(uint8_t *p, uint64_t w) {
		for (int i = 0; i < 8; i++) p[i] = (uint8_t)(w >> (8 * i));
	}
	static uint64_t rotr(uint64_t w, int c) { return (w >> c) | (w << (64 - c)); }

	void incr(uint64_t n) {
		t[0] += n;
		if (t[0] < n) t[1]++;
	}

	void compress(const uint8_t block[BLOCK]) {
		uint64_t m[16], v[16];
		for (int i = 0; i < 16; i++) m[i] = load64(block + 8 * i);
		for (int i = 0; i < 8; i++) v[i] = h[i];
		for (int i = 0; i < 8; i++) v[i + 8] = IV[i];
		v[12] ^= t[0];
		v[13] ^= t[1];
		v[14] ^= f[0];
		v[15] ^= f[1];

#define G(r, i, a, b, c, d)                                              \
	do {                                                                 \
		a = a + b + m[SIGMA[r][2 * i + 0]];                              \
		d = rotr(d ^ a, 32);                                             \
		c = c + d;                                                       \
		b = rotr(b ^ c, 24);                                             \
		a = a + b + m[SIGMA[r][2 * i + 1]];                              \
		d = rotr(d ^ a, 16);                                             \
		c = c + d;                                                       \
		b = rotr(b ^ c, 63);                                             \
	} while (0)

		for (int r = 0; r < 12; r++) {
			G(r, 0, v[0], v[4], v[8], v[12]);
			G(r, 1, v[1], v[5], v[9], v[13]);
			G(r, 2, v[2], v[6], v[10], v[14]);
			G(r, 3, v[3], v[7], v[11], v[15]);
			G(r, 4, v[0], v[5], v[10], v[15]);
			G(r, 5, v[1], v[6], v[11], v[12]);
			G(r, 6, v[2], v[7], v[8], v[13]);
			G(r, 7, v[3], v[4], v[9], v[14]);
		}
#undef G
		for (int i = 0; i < 8; i++) h[i] ^= v[i] ^ v[i + 8];
	}
};

} 
