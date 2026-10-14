
#pragma once

#include "gdpk_aes256gcm.h"
#include "gdpk_blake2b.h"

#include <cstdint>
#include <cstring>
#include <vector>
#include <string>

namespace gdpk {

inline constexpr uint8_t MAGIC[4] = {'G', 'D', 'P', 'K'};
inline constexpr uint8_t VER_MAJOR = 1, VER_MINOR = 0;
inline constexpr size_t HEADER_LEN = 96;
inline constexpr uint32_t TABLE_VERSION = 1;

inline constexpr uint16_t FLAG_TABLE_ENC = 1 << 0;
inline constexpr uint16_t FLAG_CHUNKED = 1 << 1;
inline constexpr uint16_t FLAG_TREE = 1 << 2;
inline constexpr uint16_t FLAG_VM = 1 << 3;

inline constexpr uint16_t FILE_FLAG_VIRTUALIZED = 1 << 0;

inline constexpr uint32_t EMBED_MAGIC = 0x4B504447u; 
inline constexpr size_t EMBED_FOOTER_LEN = 12;       

inline constexpr uint32_t CHUNK_SIZE = 64 * 1024;
inline constexpr size_t NONCE_LEN = 12;
inline constexpr size_t TAG_LEN = 16;

enum class FileKind : uint8_t {
	DATA = 0,
	GDSCRIPT_SOURCE = 1,
	VM_BYTECODE = 2,
	SCENE = 3,
	RESOURCE = 4,
	CONFIG = 5,
	NATIVE = 6,
};

inline uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
inline uint32_t rd32(const uint8_t *p) {
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
			((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
inline uint64_t rd64(const uint8_t *p) {
	uint64_t v = 0;
	for (int i = 0; i < 8; i++) v |= (uint64_t)p[i] << (8 * i);
	return v;
}
inline void wr32(uint8_t *p, uint32_t v) {
	p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
inline void wr64(uint8_t *p, uint64_t v) {
	for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i));
}

struct BuildKey {
	uint8_t key[32];
	uint8_t salt[8];
};

inline void derive_table_key(const BuildKey &bk, uint8_t out[32]) {
	const uint8_t *parts[2] = {bk.key, bk.salt};
	size_t lens[2] = {32, 8};
	Blake2b::kdf(out, "table", parts, lens, 2);
}

inline void derive_file_key(const BuildKey &bk, uint64_t file_index,
		uint8_t out[32]) {
	uint8_t idx[8];
	wr64(idx, file_index);
	const uint8_t *parts[3] = {bk.key, bk.salt, idx};
	size_t lens[3] = {32, 8, 8};
	Blake2b::kdf(out, "file", parts, lens, 3);
}

inline void derive_nonce_base(const uint8_t salt[8], uint32_t file_index,
		uint8_t out12[12]) {
	uint8_t msg[12];
	memcpy(msg, salt, 8);
	wr32(msg + 8, file_index);
	Blake2b::hash(msg, 12, out12, 12,
			(const uint8_t *)"gdpknonc", 8);
}

inline void derive_chunk_nonce(const uint8_t nonce_base[12], uint64_t chunk,
		uint8_t out[12]) {
	memcpy(out, nonce_base, 12);
	uint8_t ctr[8];
	wr64(ctr, chunk);
	for (int i = 0; i < 8; i++) out[NONCE_LEN - 8 + i] ^= ctr[i];
}

inline void chunk_aad(const uint8_t salt[8], uint32_t file_index,
		uint32_t chunk_index, uint8_t out[16]) {
	memcpy(out, salt, 8);
	wr32(out + 8, file_index);
	wr32(out + 12, chunk_index);
}

struct Header {
	uint16_t flags = 0;
	uint8_t salt[8] = {0};
	uint64_t table_offset = 0, table_length = 0;
	uint8_t table_nonce[12] = {0};
	uint64_t data_offset = 0, data_length = 0;
	uint64_t tree_offset = 0, tree_length = 0;

	bool has_tree() const { return (flags & FLAG_TREE) != 0; }
	bool chunked() const { return (flags & FLAG_CHUNKED) != 0; }
	bool has_vm() const { return (flags & FLAG_VM) != 0; }
};

inline bool parse_header(const uint8_t *d, size_t dlen, Header &h) {
	if (dlen < HEADER_LEN) return false;
	if (memcmp(d, MAGIC, 4) != 0) return false;
	if (d[4] != VER_MAJOR) return false; 
	h.flags = rd16(d + 6);
	memcpy(h.salt, d + 8, 8);
	h.table_offset = rd64(d + 16);
	h.table_length = rd64(d + 24);
	memcpy(h.table_nonce, d + 32, 12);
	h.data_offset = rd64(d + 44);
	h.data_length = rd64(d + 52);
	h.tree_offset = rd64(d + 60);
	h.tree_length = rd64(d + 68);
	return true;
}

struct TableEntry {
	uint32_t index = 0;      
	std::string path;        
	FileKind kind = FileKind::DATA;
	uint8_t codec = 0;       
	uint16_t flags = 0;
	uint64_t data_offset = 0; 
	uint64_t stored_size = 0; 
	uint64_t orig_size = 0;   
	uint8_t nonce_base[12] = {0};
	uint8_t digest[32] = {0}; 

	bool virtualized() const { return (flags & FILE_FLAG_VIRTUALIZED) != 0; }

	static uint64_t chunk_ct_span(uint64_t pos, uint64_t stored_size,
			uint32_t chunk_size) {
		uint64_t rem = stored_size - pos;
		uint64_t full = (uint64_t)chunk_size + TAG_LEN;
		return rem >= full ? full : rem;
	}
};

inline bool parse_table(const BuildKey &bk, const uint8_t *table_ct,
		size_t table_ct_len, const uint8_t *table_nonce,
		std::vector<TableEntry> &entries, uint8_t tree_root[32],
		bool expect_tree, uint32_t &r_chunk_size) {
	uint8_t tkey[32];
	derive_table_key(bk, tkey);

	std::vector<uint8_t> tbl(table_ct_len >= TAG_LEN ? table_ct_len - TAG_LEN : 0);
	if (table_ct_len < TAG_LEN ||
			!aes256_gcm_decrypt(tkey, table_nonce, table_ct, table_ct_len,
					bk.salt, 8, tbl.data()))
		return false;

	if (tbl.size() < 12 || rd32(tbl.data()) != TABLE_VERSION) return false;
	uint32_t count = rd32(tbl.data() + 4);
	r_chunk_size = rd32(tbl.data() + 8);
	if (r_chunk_size == 0 || r_chunk_size > (1u << 24)) return false; 
	size_t pos = 12;
	entries.clear();
	entries.reserve(count);
	for (uint32_t i = 0; i < count; i++) {
		if (pos + 2 > tbl.size()) return false;
		uint16_t plen = rd16(tbl.data() + pos);
		pos += 2;
		if (pos + plen + 28 + NONCE_LEN + 32 > tbl.size()) return false;
		TableEntry e;
		e.index = i;
		e.path.assign((const char *)tbl.data() + pos, plen);
		pos += plen;
		
		e.kind = (FileKind)tbl[pos];
		e.codec = tbl[pos + 1];
		e.flags = rd16(tbl.data() + pos + 2);
		e.data_offset = rd64(tbl.data() + pos + 4);
		e.stored_size = rd64(tbl.data() + pos + 12);
		e.orig_size = rd64(tbl.data() + pos + 20);
		pos += 28;
		memcpy(e.nonce_base, tbl.data() + pos, NONCE_LEN);
		pos += NONCE_LEN;
		memcpy(e.digest, tbl.data() + pos, 32);
		pos += 32;
		entries.push_back(e);
	}
	memset(tree_root, 0, 32);
	if (expect_tree) {
		if (pos + 32 > tbl.size()) return false;
		memcpy(tree_root, tbl.data() + pos, 32);
	}
	return true;
}

inline void hash_leaf(const uint8_t *ct, size_t ct_len, uint8_t out[32]) {
	Blake2b::hash(ct, ct_len, out, 32, (const uint8_t *)"gdpkleaf", 8);
}
inline void hash_node(const uint8_t l[32], const uint8_t r[32], uint8_t out[32]) {
	uint8_t both[64];
	memcpy(both, l, 32);
	memcpy(both + 32, r, 32);
	Blake2b::hash(both, 64, out, 32, (const uint8_t *)"gdpknode", 8);
}

inline void merkle_root(const std::vector<std::vector<uint8_t>> &leaves,
		uint8_t root[32]) {
	if (leaves.empty()) {
		memset(root, 0, 32);
		return;
	}
	std::vector<std::vector<uint8_t>> nodes = leaves;
	while (nodes.size() > 1) {
		std::vector<std::vector<uint8_t>> nxt;
		for (size_t i = 0; i < nodes.size(); i += 2) {
			const uint8_t *l = nodes[i].data();
			const uint8_t *r = (i + 1 < nodes.size()) ? nodes[i + 1].data()
					: nodes[i].data(); 
			std::vector<uint8_t> p(32);
			hash_node(l, r, p.data());
			nxt.push_back(p);
		}
		nodes = nxt;
	}
	memcpy(root, nodes[0].data(), 32);
}

inline void salt_u64_to_bytes(uint64_t salt_u64, uint8_t out[8]) {
	for (int i = 0; i < 8; i++) out[i] = (uint8_t)(salt_u64 >> (56 - 8 * i));
}

} 
