
#pragma once

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <sys/types.h>
#if defined(__APPLE__)
#include <mach-o/dyld.h>
#endif
#endif

namespace gdpk {

inline constexpr uint8_t KEY_OVERLAY_MAGIC[8] = {
	'G', 'D', 'P', 'K', 'K', 'E', 'Y', '!'};
inline constexpr size_t KEY_OVERLAY_FOOTER_LEN = 12; 
inline constexpr uint8_t KEY_OVERLAY_VER = 1;
inline constexpr uint8_t KEY_OVERLAY_MAX_SHARDS = 16; 
inline constexpr size_t KEY_OVERLAY_BLOB_FIXED = 2 + 8 + 4; 
inline constexpr uint32_t KEY_OVERLAY_BLOB_MAX =
		KEY_OVERLAY_BLOB_FIXED + KEY_OVERLAY_MAX_SHARDS * 32;

namespace key_probe_detail {

inline uint32_t rd32le(const uint8_t *p) {
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
			((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
inline uint64_t rd64le(const uint8_t *p) {
	uint64_t v = 0;
	for (int i = 0; i < 8; i++) v |= (uint64_t)p[i] << (8 * i);
	return v;
}

inline void burn(void *p, size_t n) {
	volatile uint8_t *v = (volatile uint8_t *)p;
	while (n--) *v++ = 0;
}

inline void burn(std::vector<uint8_t> &v) {
	if (!v.empty()) burn(v.data(), v.size());
	v.clear();
}

inline uint32_t crc32_ieee(const uint8_t *d, size_t n) {
	static uint32_t tbl[256];
	static bool ready = false;
	if (!ready) {
		for (uint32_t i = 0; i < 256; i++) {
			uint32_t c = i;
			for (int k = 0; k < 8; k++)
				c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
			tbl[i] = c;
		}
		ready = true;
	}
	uint32_t crc = 0xFFFFFFFFu;
	for (size_t i = 0; i < n; i++)
		crc = tbl[(crc ^ d[i]) & 0xFF] ^ (crc >> 8);
	return crc ^ 0xFFFFFFFFu;
}

inline FILE *open_self_exe() {
#if defined(_WIN32)
	
	std::vector<wchar_t> buf(MAX_PATH);
	for (;;) {
		DWORD n = GetModuleFileNameW(nullptr, buf.data(), (DWORD)buf.size());
		if (n == 0) return nullptr;
		if (n < buf.size()) return _wfopen(buf.data(), L"rb");
		if (buf.size() >= 65536) return nullptr; 
		buf.resize(buf.size() * 2);
	}
#elif defined(__APPLE__)
	uint32_t cap = 0;
	_NSGetExecutablePath(nullptr, &cap);
	if (cap == 0) return nullptr;
	std::vector<char> buf(cap);
	if (_NSGetExecutablePath(buf.data(), &cap) != 0) return nullptr;
	return fopen(buf.data(), "rb");
#else
	
	return fopen("/proc/self/exe", "rb");
#endif
}

inline int seek_abs(FILE *f, uint64_t off) {
#if defined(_WIN32)
	return _fseeki64(f, (__int64)off, SEEK_SET);
#else
	return fseeko(f, (off_t)off, SEEK_SET);
#endif
}

inline uint64_t file_len(FILE *f) {
#if defined(_WIN32)
	if (_fseeki64(f, 0, SEEK_END) != 0) return UINT64_MAX;
	__int64 n = _ftelli64(f);
#else
	if (fseeko(f, 0, SEEK_END) != 0) return UINT64_MAX;
	off_t n = ftello(f);
#endif
	return n < 0 ? UINT64_MAX : (uint64_t)n;
}

} 

inline bool probe_embedded(uint8_t key[32], uint8_t salt[8]) {
	bool ok = false;
	std::vector<uint8_t> blob;
	uint8_t foot[KEY_OVERLAY_FOOTER_LEN] = {0};

	FILE *f = key_probe_detail::open_self_exe();
	if (!f) return false;

	for (;;) { 
		uint64_t fsz = key_probe_detail::file_len(f);
		if (fsz == UINT64_MAX || fsz < KEY_OVERLAY_FOOTER_LEN) break;
		if (key_probe_detail::seek_abs(f, fsz - KEY_OVERLAY_FOOTER_LEN) != 0)
			break;
		if (fread(foot, 1, KEY_OVERLAY_FOOTER_LEN, f) !=
				KEY_OVERLAY_FOOTER_LEN)
			break;
		if (memcmp(foot + 4, KEY_OVERLAY_MAGIC, 8) != 0) break;

		uint32_t blob_len = key_probe_detail::rd32le(foot);
		if (blob_len < KEY_OVERLAY_BLOB_FIXED + 32 ||
				blob_len > KEY_OVERLAY_BLOB_MAX ||
				(uint64_t)blob_len + KEY_OVERLAY_FOOTER_LEN > fsz)
			break;

		blob.resize(blob_len);
		if (key_probe_detail::seek_abs(f,
					fsz - KEY_OVERLAY_FOOTER_LEN - blob_len) != 0)
			break;
		if (fread(blob.data(), 1, blob_len, f) != blob_len) break;

		uint8_t ver = blob[0];
		uint8_t nshards = blob[1];
		if (ver != KEY_OVERLAY_VER) break;
		if (nshards == 0 || nshards > KEY_OVERLAY_MAX_SHARDS) break;
		if (blob_len != (uint32_t)KEY_OVERLAY_BLOB_FIXED +
						(uint32_t)nshards * 32u)
			break;
		if (key_probe_detail::crc32_ieee(blob.data(), blob_len - 4) !=
				key_probe_detail::rd32le(blob.data() + blob_len - 4))
			break;

		memset(key, 0, 32);
		const uint8_t *sp = blob.data() + 10;
		for (uint32_t s = 0; s < nshards; s++)
			for (int i = 0; i < 32; i++) key[i] ^= sp[s * 32 + i];

		uint64_t sv = key_probe_detail::rd64le(blob.data() + 2);
		for (int i = 0; i < 8; i++) salt[i] = (uint8_t)(sv >> (56 - 8 * i));
		ok = true;
		break;
	}

	key_probe_detail::burn(blob);
	key_probe_detail::burn(foot, sizeof(foot));
	fclose(f);
	if (!ok) {
		key_probe_detail::burn(key, 32);
		key_probe_detail::burn(salt, 8);
	}
	return ok;
}

} 
