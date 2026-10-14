
#pragma once

#include <godot_cpp/classes/object.hpp>
#include <godot_cpp/classes/file_access.hpp>
#include <godot_cpp/templates/hash_map.hpp>
#include <godot_cpp/variant/array.hpp>
#include <godot_cpp/variant/callable.hpp>
#include <godot_cpp/variant/dictionary.hpp>
#include <godot_cpp/variant/packed_byte_array.hpp>
#include <godot_cpp/variant/string.hpp>

#include "../shared/gdpk_format.h"
#include "../shared/gdpk_strpool.h"
#include "gvm_vm.h"

namespace godot {

class Gdpk : public Object {
	GDCLASS(Gdpk, Object);

public:
	
	struct CipherVtable {
		
		bool (*aead_open)(const uint8_t key[32], const uint8_t nonce[12],
				const uint8_t *ct, size_t ct_len,
				const uint8_t *aad, size_t aad_len, uint8_t *out) = nullptr;
		
		void (*sha256)(const uint8_t *data, size_t len, uint8_t out[32]) = nullptr;
	};

protected:
	static void _bind_methods();

public:
	static Gdpk *get_singleton();

	Gdpk();
	~Gdpk() override;

	bool open_container(String path);
	bool verify_integrity();
	Dictionary container_info();
	PackedByteArray read_file(String res_path);
	bool has_file(String res_path) const;
	String get_last_error() const;

	
	String str_at(String pool_path, int idx);

	bool vm_load(String res_path);
	
	Variant vm_call(int func_idx, const Array &args);
	
	int vm_func_index(String name);
	
	void vm_register_host_call(String name, const Callable &cb);
	
	void vm_set_self(Object *obj);

	void set_cipher(const CipherVtable &vt);

private:
	Ref<FileAccess> file;
	String pack_path;
	gdpk::Header hdr;
	gdpk::BuildKey bk;
	bool ready = false;
	String last_error;
	uint32_t chunk_size = gdpk::CHUNK_SIZE; 
	uint8_t tree_root[32] = {0};

	std::vector<gdpk::TableEntry> entries;
	HashMap<String, int32_t> by_path;
	CipherVtable cipher;
	Ref<GvmVM> vm;

	
	static constexpr int STRPOOL_CACHE_MAX = 16;
	HashMap<String, gdpk::StrPoolPlain> strpool_cache;
	std::vector<String> strpool_order; 

	bool fail(const String &msg);
	
	const gdpk::StrPoolPlain *get_strpool(const String &pool_path);
	
	void drop_strpools();
	
	bool read_entry(const gdpk::TableEntry &e, PackedByteArray &r_out);
	
	bool decrypt_chunk(const gdpk::TableEntry &e, const uint8_t *ct,
			size_t ct_len, uint32_t chunk_index, PackedByteArray &r_out,
			uint32_t &r_len);
};

} 
