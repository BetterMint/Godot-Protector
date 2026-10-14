
#include "gdpk_pack_source.h"

#include "core/crypto/crypto_core.h"   
#include "core/io/compression.h"       
#include "core/error/error_macros.h"

#ifdef GDPK_HAS_KEY_SHARD
#include "../key_shard.h"              
#endif

#include "../shared/gdpk_key_probe.h"

#ifdef GDPK_VERBOSE_ERRORS
#define GDPK_ERR(m) ERR_PRINT(m)
#else
#define GDPK_ERR(m) ((void)0)
#endif

namespace {

static bool sha256_check(const uint8_t *data, size_t len,
		const uint8_t digest[32]) {
#ifdef GDPK_NO_CRYPTO_CORE
	(void)data; (void)len; (void)digest;
	GDPK_ERR("gdpk: plaintext sha256 check disabled");
	return true;
#else
	uint8_t got[32];
	CryptoCore::sha256(data, len, got);
	return memcmp(got, digest, 32) == 0;
#endif
}

static bool zlib_inflate(const uint8_t *src, size_t src_len, uint8_t *dst,
		size_t dst_size) {
	int written = Compression::decompress(dst, (int)dst_size, src,
			(int)src_len, Compression::MODE_DEFLATE);
	return written == (int)dst_size;
}

} 

GdpkPackSource::GdpkPackSource() {}

GdpkPackSource::~GdpkPackSource() {
	
}

bool GdpkPackSource::try_open_pack(const String &p_path, bool p_replace_files,
		uint64_t p_offset) {
	
	String open_path = p_path;
	Ref<FileAccess> f = FileAccess::open(open_path, FileAccess::READ);
	if (f.is_null() && p_path.get_extension() == "pck") {
		open_path = p_path.get_basename() + ".gdpk";
		f = FileAccess::open(open_path, FileAccess::READ);
	}
	if (f.is_null()) return false;

	uint64_t cbase = p_offset;
	f->seek(cbase);
	uint8_t hdr[gdpk::HEADER_LEN];
	gdpk::Header h;
	bool is_gdpk =
			f->get_buffer(hdr, gdpk::HEADER_LEN) == gdpk::HEADER_LEN &&
			gdpk::parse_header(hdr, gdpk::HEADER_LEN, h);
	if (!is_gdpk) {
		
		uint64_t fsz = f->get_length();
		
		if (fsz >= gdpk::KEY_OVERLAY_FOOTER_LEN) {
			uint8_t tail[gdpk::KEY_OVERLAY_FOOTER_LEN];
			f->seek(fsz - gdpk::KEY_OVERLAY_FOOTER_LEN);
			if (f->get_buffer(tail, gdpk::KEY_OVERLAY_FOOTER_LEN) ==
							gdpk::KEY_OVERLAY_FOOTER_LEN &&
					memcmp(tail + 4, gdpk::KEY_OVERLAY_MAGIC, 8) == 0) {
				uint32_t olen = gdpk::rd32(tail);
				if ((uint64_t)olen + gdpk::KEY_OVERLAY_FOOTER_LEN <= fsz)
					fsz -= gdpk::KEY_OVERLAY_FOOTER_LEN + olen;
			}
		}
		if (fsz >= gdpk::HEADER_LEN + gdpk::EMBED_FOOTER_LEN) {
			uint8_t foot[gdpk::EMBED_FOOTER_LEN];
			f->seek(fsz - gdpk::EMBED_FOOTER_LEN);
			if (f->get_buffer(foot, gdpk::EMBED_FOOTER_LEN) ==
							gdpk::EMBED_FOOTER_LEN &&
					gdpk::rd32(foot + gdpk::EMBED_FOOTER_LEN - 4) ==
							gdpk::EMBED_MAGIC) {
				uint64_t elen = gdpk::rd64(foot);
				if (elen >= gdpk::HEADER_LEN &&
						elen <= fsz - gdpk::EMBED_FOOTER_LEN) {
					uint64_t base = fsz - gdpk::EMBED_FOOTER_LEN - elen;
					f->seek(base);
					is_gdpk =
							f->get_buffer(hdr, gdpk::HEADER_LEN) ==
									gdpk::HEADER_LEN &&
							gdpk::parse_header(hdr, gdpk::HEADER_LEN, h);
					if (is_gdpk) cbase = base;
				}
			}
		}
		if (!is_gdpk) return false; 
	}

	uint8_t want_salt[8];
#ifdef GDPK_HAS_KEY_SHARD
	gdpk::salt_u64_to_bytes(gdpk::BUILD_SALT, want_salt);
	gdpk::rebuild_key(bk.key);
#else
	if (!gdpk::probe_embedded(bk.key, want_salt)) {
		GDPK_ERR("gdpk: no key material — built without key_shard.h and no embedded-key overlay found");
		return false;
	}
#endif
	if (memcmp(want_salt, h.salt, 8) != 0) {
		GDPK_ERR("gdpk: build salt mismatch — key material belongs to a different build");
		return false;
	}

	memcpy(bk.salt, h.salt, 8);

	Vector<uint8_t> table_ct;
	table_ct.resize(h.table_length);
	f->seek(cbase + h.table_offset);
	if (f->get_buffer(table_ct.ptrw(), h.table_length) != h.table_length)
		return false;

	std::vector<gdpk::TableEntry> raw;
	uint32_t cs = gdpk::CHUNK_SIZE;
	if (!gdpk::parse_table(bk, table_ct.ptr(), h.table_length, h.table_nonce,
			raw, tree_root, h.has_tree(), cs)) {
		GDPK_ERR("gdpk: table decryption failed — wrong key or tampered container");
		return false;
	}
	chunk_size = cs;

	pack_path = open_path;
	base_offset = cbase;
	header_flags = h.flags;
	entries.resize((int)raw.size());
	by_path.clear();
	for (size_t i = 0; i < raw.size(); i++) {
		Entry &e = entries[(int)i];
		const gdpk::TableEntry &r = raw[i];
		e.index = r.index;
		e.path = String(r.path.c_str());
		e.kind = (uint8_t)r.kind;
		e.codec = r.codec;
		e.flags = r.flags;
		e.data_offset = r.data_offset;
		e.stored_size = r.stored_size;
		e.orig_size = r.orig_size;
		memcpy(e.nonce_base, r.nonce_base, gdpk::NONCE_LEN);
		memcpy(e.digest, r.digest, 32);
		by_path[e.path] = (int)i;

		static const uint8_t zero_md5[16] = {0};
		PackedData::get_singleton()->add_path(open_path, e.path,
				cbase + e.data_offset, e.orig_size, zero_md5,
				this, p_replace_files, false);
	}

	file = f;
	ready = true;
	return true;
}

Ref<FileAccess> GdpkPackSource::get_file(const String &p_path,
		PackedData::PackedFile *p_file) {
	if (!ready) return Ref<FileAccess>();
	const int *idx = by_path.getptr(p_path);
	if (!idx) return Ref<FileAccess>();
	return Ref<FileAccess>(memnew(FileAccessGdpk(this, *idx)));
}

bool GdpkPackSource::decrypt_chunk(const Entry &e, uint64_t chunk_index,
		uint8_t *out, uint32_t &r_len) const {
	uint64_t ct_span = (uint64_t)chunk_size + gdpk::TAG_LEN;
	uint64_t rel = chunk_index * ct_span;
	if (rel >= e.stored_size) return false;
	uint64_t take = e.stored_size - rel;
	if (take > ct_span) take = ct_span;

	Vector<uint8_t> ct;
	ct.resize((int)take);
	file->seek(base_offset + e.data_offset + rel);
	if (file->get_buffer(ct.ptrw(), take) != take) return false;

	uint8_t aad[16], nonce[gdpk::NONCE_LEN], fkey[32];
	gdpk::chunk_aad(bk.salt, e.index, (uint32_t)chunk_index, aad);
	gdpk::derive_chunk_nonce(e.nonce_base, chunk_index, nonce);
	gdpk::derive_file_key(bk, e.index, fkey);

	if (!gdpk::aes256_gcm_decrypt(fkey, nonce, ct.ptr(), (size_t)take,
			aad, sizeof(aad), out))
		return false; 
	r_len = (uint32_t)(take - gdpk::TAG_LEN);
	return true;
}

bool GdpkPackSource::read_body(const Entry &e, Vector<uint8_t> &r_body) const {
	Vector<uint8_t> ct;
	ct.resize((int)e.stored_size);
	file->seek(base_offset + e.data_offset);
	if (file->get_buffer(ct.ptrw(), e.stored_size) != e.stored_size)
		return false;

	r_body.clear();
	uint8_t fkey[32];
	gdpk::derive_file_key(bk, e.index, fkey);

	uint64_t pos = 0;
	uint32_t c = 0;
	while (pos < e.stored_size) {
		uint64_t take = gdpk::TableEntry::chunk_ct_span(pos, e.stored_size,
				chunk_size);
		uint8_t aad[16], nonce[gdpk::NONCE_LEN];
		gdpk::chunk_aad(bk.salt, e.index, c, aad);
		gdpk::derive_chunk_nonce(e.nonce_base, c, nonce);

		size_t plain_len = (size_t)(take - gdpk::TAG_LEN);
		size_t at = r_body.size();
		r_body.resize(at + plain_len);
		if (!gdpk::aes256_gcm_decrypt(fkey, nonce, ct.ptr() + pos,
				(size_t)take, aad, sizeof(aad), r_body.ptrw() + at)) {
			r_body.clear();
			return false;
		}
		pos += take;
		c++;
	}
	return true;
}

bool GdpkPackSource::inflate_body(const Vector<uint8_t> &body,
		uint64_t orig_size, Vector<uint8_t> &r_out) {
	r_out.resize((int)orig_size);
	return zlib_inflate(body.ptr(), body.size(), r_out.ptrw(), orig_size);
}

bool GdpkPackSource::verify_integrity() {
	if (!ready || !(header_flags & gdpk::FLAG_TREE)) return ready;

	std::vector<std::vector<uint8_t>> leaves;
	Vector<uint8_t> ct_span_buf;
	ct_span_buf.resize((int)chunk_size + (int)gdpk::TAG_LEN);
	for (const Entry &e : entries) {
		file->seek(base_offset + e.data_offset);
		uint64_t pos = 0;
		while (pos < e.stored_size) {
			uint64_t take = gdpk::TableEntry::chunk_ct_span(pos, e.stored_size,
					chunk_size);
			if (file->get_buffer(ct_span_buf.ptrw(), take) != take)
				return false;
			std::vector<uint8_t> leaf(32);
			gdpk::hash_leaf(ct_span_buf.ptr(), (size_t)take, leaf.data());
			leaves.push_back(leaf);
			pos += take;
		}
	}
	uint8_t root[32];
	gdpk::merkle_root(leaves, root);
	return memcmp(root, tree_root, 32) == 0;
}

FileAccessGdpk::FileAccessGdpk(GdpkPackSource *p_src, int p_entry)
		: src(p_src), entry_idx(p_entry) {
	const Entry &e = src->entries[entry_idx];
	logical_len = e.orig_size;
	chunk_buf.resize(src->chunk_size);
}

Error FileAccessGdpk::open_internal(const String &p_path, int p_mode_flags) {
	
	return ERR_UNAVAILABLE;
}

bool FileAccessGdpk::is_open() const { return src != nullptr; }
String FileAccessGdpk::get_path() const {
	return src ? src->entries[entry_idx].path : String();
}
String FileAccessGdpk::get_path_absolute() const {
	return src ? src->pack_path + "::" + src->entries[entry_idx].path : String();
}

void FileAccessGdpk::seek(uint64_t p_position) {
	pos = p_position > logical_len ? logical_len : p_position;
}
void FileAccessGdpk::seek_end(int64_t p_position) {
	int64_t np = (int64_t)logical_len + p_position;
	pos = np < 0 ? 0 : (uint64_t)np;
}
uint64_t FileAccessGdpk::get_position() const { return pos; }
uint64_t FileAccessGdpk::get_length() const { return logical_len; }
bool FileAccessGdpk::eof_reached() const { return !src || pos >= logical_len; }

bool FileAccessGdpk::ensure_chunk(uint64_t chunk_index) const {
	if (cached_chunk == (int)chunk_index) return true;
	const Entry &e = src->entries[entry_idx];
	if (!src->decrypt_chunk(e, chunk_index, chunk_buf.ptrw(), chunk_len)) {
		last_error = ERR_FILE_CORRUPT;
		return false;
	}
	cached_chunk = (int)chunk_index;
	return true;
}

bool FileAccessGdpk::ensure_mem() const {
	if (mem_loaded) return true;
	const Entry &e = src->entries[entry_idx];
	Vector<uint8_t> body;
	if (!src->read_body(e, body)) {
		last_error = ERR_FILE_CORRUPT;
		return false;
	}
	if (e.codec == 1) {
		if (!GdpkPackSource::inflate_body(body, e.orig_size, mem)) {
			last_error = ERR_FILE_CORRUPT;
			return false;
		}
	} else {
		mem = body; 
	}
	if (!sha256_check(mem.ptr(), mem.size(), e.digest)) {
		last_error = ERR_FILE_CORRUPT;
		GDPK_ERR("gdpk: sha256 mismatch on " + e.path);
		return false;
	}
	mem_loaded = true;
	return true;
}

uint8_t FileAccessGdpk::get_8() const {
	uint8_t b = 0;
	get_buffer(&b, 1);
	return b;
}

uint64_t FileAccessGdpk::get_buffer(uint8_t *p_dst, uint64_t p_length) const {
	if (!src || !p_dst || p_length == 0) return 0;
	const Entry &e = src->entries[entry_idx];
	uint64_t want = p_length;
	if (pos + want > logical_len) want = logical_len - pos;
	uint64_t done = 0;

	if (e.codec == 1) {
		
		if (!ensure_mem()) return 0;
		memcpy(p_dst, mem.ptr() + pos, (size_t)want);
		pos += want;
		return want;
	}

	while (done < want) {
		uint64_t chunk_index = (pos + done) / src->chunk_size;
		uint64_t in_chunk = (pos + done) % src->chunk_size;
		if (!ensure_chunk(chunk_index)) return done;
		uint64_t avail = chunk_len - in_chunk;
		uint64_t n = want - done < avail ? want - done : avail;
		memcpy(p_dst + done, chunk_buf.ptr() + in_chunk, (size_t)n);
		done += n;
	}
	pos += want;
	last_error = OK;
	return want;
}

Error FileAccessGdpk::get_error() const { return last_error; }
void FileAccessGdpk::flush() {}
void FileAccessGdpk::store_8(uint8_t) {}
void FileAccessGdpk::store_buffer(const uint8_t *, uint64_t) {}
bool FileAccessGdpk::file_exists(const String &) { return false; }

void FileAccessGdpk::close() {
	src = nullptr;
	chunk_buf.clear();
	mem.clear();
}
