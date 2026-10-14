
#include "gdpk.h"

#include <godot_cpp/classes/engine.hpp>
#include <godot_cpp/classes/hashing_context.hpp>
#include <godot_cpp/core/class_db.hpp>
#include <godot_cpp/variant/char_string.hpp>
#include <godot_cpp/variant/utility_functions.hpp>

#include <cstdio>
#include <cstring>

#ifdef GDPK_HAS_KEY_SHARD
#include "../key_shard.h"
#else
#include "../shared/gdpk_key_probe.h"
#endif

#ifdef GDPK_VERBOSE_ERRORS
#define GDPK_DIAG(msg) (msg)
#else
#define GDPK_DIAG(msg) "request failed"
#endif

namespace godot {

static Gdpk *singleton = nullptr;
Gdpk *Gdpk::get_singleton() { return singleton; }

static void _hc_sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
	Ref<HashingContext> hc;
	hc.instantiate();
	if (hc.is_null()) { memset(out, 0, 32); return; }
	PackedByteArray pba;
	pba.resize((int64_t)len);
	if (len) memcpy(pba.ptrw(), data, len); 
	if (hc->start(HashingContext::HASH_SHA256) == OK) {
		hc->update(pba);
		PackedByteArray d = hc->finish();
		if (d.size() == 32) memcpy(out, d.ptr(), 32);
	}
}

static void _secure_bzero(void *ptr, size_t n) {
	volatile uint8_t *v = (volatile uint8_t *)ptr;
	while (n--) *v++ = 0;
}

void Gdpk::_bind_methods() {
	ClassDB::bind_method(D_METHOD("open_container", "path"), &Gdpk::open_container);
	ClassDB::bind_method(D_METHOD("read_file", "res_path"), &Gdpk::read_file);
	ClassDB::bind_method(D_METHOD("verify_integrity"), &Gdpk::verify_integrity);
	ClassDB::bind_method(D_METHOD("container_info"), &Gdpk::container_info);
	ClassDB::bind_method(D_METHOD("has_file", "res_path"), &Gdpk::has_file);
	ClassDB::bind_method(D_METHOD("get_last_error"), &Gdpk::get_last_error);
	ClassDB::bind_method(D_METHOD("vm_load", "res_path"), &Gdpk::vm_load);
	ClassDB::bind_method(D_METHOD("vm_call", "func_idx", "args"), &Gdpk::vm_call);
	ClassDB::bind_method(D_METHOD("vm_register_host_call", "name", "cb"),
			&Gdpk::vm_register_host_call);
	ClassDB::bind_method(D_METHOD("vm_func_index", "name"), &Gdpk::vm_func_index);
	ClassDB::bind_method(D_METHOD("vm_set_self", "obj"), &Gdpk::vm_set_self);
	ClassDB::bind_method(D_METHOD("str_at", "pool_path", "idx"), &Gdpk::str_at);
}

Gdpk::Gdpk() {
	singleton = this;
	cipher.aead_open = gdpk::aes256_gcm_decrypt;
	cipher.sha256 = _hc_sha256;
	vm.instantiate();
}
Gdpk::~Gdpk() {
	if (singleton == this) singleton = nullptr;
	drop_strpools();
	_secure_bzero(bk.key, sizeof(bk.key));
}

bool Gdpk::fail(const String &msg) {
	last_error = msg;
	UtilityFunctions::push_error("Gdpk: " + msg);
	return false;
}
String Gdpk::get_last_error() const { return last_error; }

void Gdpk::set_cipher(const CipherVtable &vt) {
	cipher = vt;
	if (!cipher.aead_open) cipher.aead_open = gdpk::aes256_gcm_decrypt;
}

bool Gdpk::open_container(String path) {
	ready = false;
	drop_strpools();
	file = FileAccess::open(path, FileAccess::READ);
	if (file.is_null())
		return fail("cannot open " + path + ": " +
				String::num_int64((int)FileAccess::get_open_error()));

	uint8_t raw_hdr[gdpk::HEADER_LEN];
	if (file->get_buffer(raw_hdr, gdpk::HEADER_LEN) != gdpk::HEADER_LEN ||
			!gdpk::parse_header(raw_hdr, gdpk::HEADER_LEN, hdr))
		return fail("not a GDPK v" + String::num_int64(gdpk::VER_MAJOR) + " container");

	uint8_t want_salt[8];
#ifdef GDPK_HAS_KEY_SHARD
	gdpk::salt_u64_to_bytes(gdpk::BUILD_SALT, want_salt);
	gdpk::rebuild_key(bk.key);
#else
	if (!gdpk::probe_embedded(bk.key, want_salt))
		return fail(GDPK_DIAG("no key material — binary built without "
				"key_shard.h and carries no embedded-key overlay"));
#endif
	if (memcmp(want_salt, hdr.salt, 8) != 0) {
		_secure_bzero(bk.key, sizeof(bk.key));
		return fail(GDPK_DIAG("build salt mismatch — key material belongs "
				"to a different build"));
	}

	memcpy(bk.salt, hdr.salt, 8);

	PackedByteArray table_ct;
	table_ct.resize((int64_t)hdr.table_length);
	file->seek(hdr.table_offset);
	if (file->get_buffer(table_ct.ptrw(), hdr.table_length) != hdr.table_length)
		return fail("table read truncated");

	uint32_t cs = gdpk::CHUNK_SIZE;
	if (!gdpk::parse_table(bk, table_ct.ptr(), (size_t)hdr.table_length,
			hdr.table_nonce, entries, tree_root, hdr.has_tree(), cs)) {
		_secure_bzero(bk.key, sizeof(bk.key));
		return fail("table decryption failed — wrong key or tampered file");
	}
	chunk_size = cs;

	by_path.clear();
	for (const gdpk::TableEntry &e : entries)
		by_path[String(e.path.c_str())] = (int32_t)e.index;

	pack_path = path;
	ready = true;
	return true;
}

bool Gdpk::has_file(String res_path) const {
	return ready && by_path.has(res_path);
}

bool Gdpk::decrypt_chunk(const gdpk::TableEntry &e, const uint8_t *ct,
		size_t ct_len, uint32_t chunk_index, PackedByteArray &r_out,
		uint32_t &r_len) {
	uint8_t aad[16], nonce[gdpk::NONCE_LEN], fkey[32];
	gdpk::chunk_aad(bk.salt, e.index, chunk_index, aad);
	gdpk::derive_chunk_nonce(e.nonce_base, chunk_index, nonce);
	gdpk::derive_file_key(bk, e.index, fkey);

	r_out.resize((int64_t)(ct_len - gdpk::TAG_LEN));
	if (!cipher.aead_open(fkey, nonce, ct, ct_len, aad, sizeof(aad),
			r_out.ptrw())) {
		r_len = 0;
		return false;
	}
	r_len = (uint32_t)(ct_len - gdpk::TAG_LEN);
	return true;
}

bool Gdpk::read_entry(const gdpk::TableEntry &e, PackedByteArray &r_out) {
	
	PackedByteArray raw;
	raw.resize((int64_t)e.stored_size);
	file->seek(e.data_offset);
	if (e.stored_size && file->get_buffer(raw.ptrw(), e.stored_size) != e.stored_size)
		return fail(e.path.c_str() + String(": short read"));

	PackedByteArray body;
	uint64_t pos = 0;
	uint32_t c = 0;
	while (pos < e.stored_size) {
		uint64_t take = gdpk::TableEntry::chunk_ct_span(pos, e.stored_size,
				chunk_size);
		PackedByteArray pt;
		uint32_t pt_len = 0;
		if (!decrypt_chunk(e, raw.ptr() + pos, (size_t)take, c, pt, pt_len))
			return fail(e.path.c_str() + String(": chunk ") + String::num_int64(c) +
					" failed authentication");
		body.append_array(pt);
		pos += take;
		c++;
	}

	PackedByteArray plain = body;
	if (e.codec == 1) {
		
		plain = body.decompress((int64_t)e.orig_size,
				PackedByteArray::COMPRESSION_DEFLATE);
		if (plain.size() != (int64_t)e.orig_size)
			return fail(e.path.c_str() + String(": inflate failed"));
	}
	if (cipher.sha256) {
		uint8_t got[32];
		cipher.sha256(plain.ptr(), plain.size(), got);
		if (memcmp(got, e.digest, 32) != 0)
			return fail(e.path.c_str() + String(": plaintext sha256 mismatch"));
	}
	r_out = plain;
	return true;
}

PackedByteArray Gdpk::read_file(String res_path) {
	PackedByteArray out;
	if (!ready) { fail("no container open"); return out; }
	const int32_t *idx = by_path.getptr(res_path);
	if (!idx) { fail(res_path + ": not in container"); return out; }
	read_entry(entries[*idx], out);
	return out;
}

void Gdpk::drop_strpools() {
	for (const String &k : strpool_order) {
		gdpk::StrPoolPlain *p = strpool_cache.getptr(k);
		if (p) gdpk::burn_strpool(*p);
	}
	strpool_cache.clear();
	strpool_order.clear();
}

const gdpk::StrPoolPlain *Gdpk::get_strpool(const String &pool_path) {
	if (const gdpk::StrPoolPlain *hit = strpool_cache.getptr(pool_path))
		return hit;

	String res = pool_path;
	if (!by_path.has(res)) {
		String with_ext = res + ".gvms";
		String swapped = res.get_basename() + ".gvms";
		if (by_path.has(with_ext)) res = with_ext;
		else if (by_path.has(swapped)) res = swapped;
	}
	PackedByteArray blob = read_file(res);
	if (blob.is_empty()) return nullptr; 

	CharString name = pool_path.utf8();
	uint8_t pkey[32];
	gdpk::derive_strpool_key(bk, (const uint8_t *)name.get_data(),
			(size_t)name.length(), pkey);
	gdpk::StrPoolPlain plain;
	bool ok = gdpk::parse_strpool(blob.ptr(), (size_t)blob.size(), pkey,
			plain, cipher.aead_open);
	_secure_bzero(pkey, sizeof(pkey));
	if (!ok) {
		fail(GDPK_DIAG(pool_path + ": stringpool decryption failed — wrong "
				"key or tampered pool"));
		return nullptr;
	}

	while ((int)strpool_order.size() >= STRPOOL_CACHE_MAX) {
		gdpk::StrPoolPlain *old = strpool_cache.getptr(strpool_order.front());
		if (old) gdpk::burn_strpool(*old);
		strpool_cache.erase(strpool_order.front());
		strpool_order.erase(strpool_order.begin());
	}
	strpool_cache[pool_path] = plain;
	strpool_order.push_back(pool_path);
	gdpk::burn_strpool(plain); 
	return strpool_cache.getptr(pool_path);
}

String Gdpk::str_at(String pool_path, int idx) {
	if (!ready) { fail("no container open"); return String(); }
	if (idx < 0) {
		fail(GDPK_DIAG("str_at: negative index"));
		return String();
	}
	const gdpk::StrPoolPlain *pool = get_strpool(pool_path);
	if (!pool) return String();

	const uint8_t *p = nullptr;
	uint32_t n = 0;
	if (!gdpk::strpool_at(*pool, (uint32_t)idx, p, n)) {
		fail(GDPK_DIAG(pool_path + ": str_at index out of range"));
		return String();
	}
	if (!p || n == 0) return String();
	return String::utf8((const char *)p, (int)n);
}

bool Gdpk::verify_integrity() {
	if (!ready) return fail("no container open");
	if (!hdr.has_tree()) return true;

	std::vector<std::vector<uint8_t>> leaves;
	PackedByteArray buf;
	buf.resize((int64_t)chunk_size + (int64_t)gdpk::TAG_LEN);
	for (const gdpk::TableEntry &e : entries) {
		file->seek(e.data_offset);
		uint64_t pos = 0;
		while (pos < e.stored_size) {
			uint64_t take = gdpk::TableEntry::chunk_ct_span(pos, e.stored_size,
					chunk_size);
			if (file->get_buffer(buf.ptrw(), take) != take)
				return fail("tree re-hash: short read");
			std::vector<uint8_t> leaf(32);
			gdpk::hash_leaf(buf.ptr(), (size_t)take, leaf.data());
			leaves.push_back(leaf);
			pos += take;
		}
	}
	uint8_t root[32];
	gdpk::merkle_root(leaves, root);
	if (memcmp(root, tree_root, 32) != 0)
		return fail("integrity tree root mismatch");
	return true;
}

Dictionary Gdpk::container_info() {
	Dictionary d;
	d["ok"] = ready;
	if (!ready) return d;
	Dictionary flags;
	flags["table_encrypted"] = (hdr.flags & gdpk::FLAG_TABLE_ENC) != 0;
	flags["chunked"] = (hdr.flags & gdpk::FLAG_CHUNKED) != 0;
	flags["integrity_tree"] = (hdr.flags & gdpk::FLAG_TREE) != 0;
	flags["vm_payload"] = (hdr.flags & gdpk::FLAG_VM) != 0;
	d["flags"] = flags;
	char hex[17];
	for (int i = 0; i < 8; i++) snprintf(hex + i * 2, 3, "%02x", hdr.salt[i]);
	hex[16] = 0;
	d["salt"] = String(hex);
	Array files;
	for (const gdpk::TableEntry &e : entries) {
		Dictionary f;
		f["path"] = String(e.path.c_str());
		f["index"] = (int)e.index;
		f["kind"] = (int)e.kind;
		f["codec"] = (int)e.codec;
		f["size"] = (int64_t)e.orig_size;
		f["stored_size"] = (int64_t)e.stored_size;
		f["virtualized"] = e.virtualized();
		files.push_back(f);
	}
	d["files"] = files;
	d["file_count"] = (int)entries.size();
	return d;
}

bool Gdpk::vm_load(String res_path) {
	PackedByteArray image = read_file(res_path);
	if (image.is_empty()) return false;
	String err;
	if (!vm->load_image(image, err)) return fail(err);
	return true;
}

Variant Gdpk::vm_call(int func_idx, const Array &args) {
	return vm->call_func(func_idx, args);
}

void Gdpk::vm_register_host_call(String name, const Callable &cb) {
	vm->set_host_call(StringName(name), cb);
}

int Gdpk::vm_func_index(String name) {
	return vm->func_index_by_name(name);
}

void Gdpk::vm_set_self(Object *obj) {
	vm->set_self(obj);
	
	vm->run_member_init();
}

} 
