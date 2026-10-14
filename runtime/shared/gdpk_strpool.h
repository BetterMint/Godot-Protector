
#pragma once

#include <cstdint>
#include <cstring>
#include <utility>
#include <vector>

#include "gdpk_format.h"

namespace gdpk {

inline constexpr uint8_t STRPOOL_MAGIC[4] = {'G', 'V', 'M', 'S'};
inline constexpr uint8_t STRPOOL_VER = 1;
inline constexpr size_t STRPOOL_HDR_LEN = 21; 

struct StrPoolPlain {
	std::vector<uint32_t> offsets; 
	std::vector<uint8_t> text;     
};

typedef bool (*StrPoolAeadOpen)(const uint8_t key[32], const uint8_t nonce[12],
		const uint8_t *ct, size_t ct_len, const uint8_t *aad, size_t aad_len,
		uint8_t *out);

inline void derive_strpool_key(const BuildKey &bk, const uint8_t *pool_name,
		size_t pool_name_len, uint8_t out[32]) {
	const uint8_t *parts[3] = {bk.key, bk.salt, pool_name};
	size_t lens[3] = {32, 8, pool_name_len};
	Blake2b::kdf(out, "strp", parts, lens, 3);
}

inline void burn_strpool(StrPoolPlain &p) {
	if (!p.text.empty()) {
		volatile uint8_t *v = p.text.data();
		for (size_t i = 0; i < p.text.size(); i++) v[i] = 0;
	}
	p.text.clear();
	p.offsets.clear();
}

inline bool parse_strpool(const uint8_t *d, size_t dlen, const uint8_t key[32],
		StrPoolPlain &out, StrPoolAeadOpen aead = nullptr) {
	out.offsets.clear();
	out.text.clear();
	if (!aead) aead = aes256_gcm_decrypt;
	if (!d || dlen < STRPOOL_HDR_LEN + TAG_LEN) return false;
	if (memcmp(d, STRPOOL_MAGIC, 4) != 0) return false;
	if (d[4] != STRPOOL_VER) return false;

	uint32_t count = rd32(d + 5);
	const uint8_t *nonce = d + 9; 
	size_t ct_off = STRPOOL_HDR_LEN + (size_t)count * 4;
	if (ct_off >= dlen || dlen - ct_off < TAG_LEN) return false;
	const uint8_t *ct = d + ct_off;
	size_t ct_len = dlen - ct_off;
	uint64_t pt_len = (uint64_t)ct_len - TAG_LEN;
	if (pt_len > UINT32_MAX) return false;

	std::vector<uint32_t> offs(count);
	uint32_t prev = 0;
	for (uint32_t i = 0; i < count; i++) {
		offs[i] = rd32(d + STRPOOL_HDR_LEN + (size_t)i * 4);
		if (offs[i] < prev || (uint64_t)offs[i] > pt_len) return false;
		prev = offs[i];
	}

	out.text.resize((size_t)pt_len);
	uint8_t sink = 0; 
	uint8_t *dst = pt_len ? out.text.data() : &sink;
	if (!aead(key, nonce, ct, ct_len, d, ct_off, dst)) {
		
		burn_strpool(out);
		return false;
	}
	out.offsets = std::move(offs);
	return true;
}

inline bool strpool_at(const StrPoolPlain &pool, uint32_t idx,
		const uint8_t *&r_ptr, uint32_t &r_len) {
	if (idx >= pool.offsets.size()) return false;
	uint64_t beg = pool.offsets[idx];
	uint64_t end = (idx + 1 < (uint32_t)pool.offsets.size())
			? pool.offsets[idx + 1]
			: (uint64_t)pool.text.size();
	if (end < beg || end > pool.text.size()) return false;
	r_ptr = pool.text.empty() ? nullptr : pool.text.data() + beg;
	r_len = (uint32_t)(end - beg);
	return true;
}

} 
