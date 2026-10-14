
#pragma once

#include "core/io/file_access.h"
#include "core/io/file_access_pack.h"
#include "core/templates/hash_map.h"
#include "core/templates/vector.h"

#include "../shared/gdpk_format.h"

class FileAccessGdpk;

class GdpkPackSource : public PackSource {
public:
	GdpkPackSource();
	virtual ~GdpkPackSource();

	virtual bool try_open_pack(const String &p_path, bool p_replace_files,
			uint64_t p_offset) override;
	virtual Ref<FileAccess> get_file(const String &p_path,
			PackedData::PackedFile *p_file) override;

	bool verify_integrity();

private:
	friend class FileAccessGdpk;

	struct Entry {
		uint32_t index = 0;
		String path;
		uint8_t kind = 0;
		uint8_t codec = 0;    
		uint16_t flags = 0;
		uint64_t data_offset = 0; 
		uint64_t stored_size = 0; 
		uint64_t orig_size = 0;   
		uint8_t nonce_base[gdpk::NONCE_LEN] = {0};
		uint8_t digest[32] = {0};
		bool virtualized() const { return flags & gdpk::FILE_FLAG_VIRTUALIZED; }
	};

	bool decrypt_chunk(const Entry &e, uint64_t chunk_index, uint8_t *out,
			uint32_t &r_len) const;
	
	bool read_body(const Entry &e, Vector<uint8_t> &r_body) const;
	
	static bool inflate_body(const Vector<uint8_t> &body, uint64_t orig_size,
			Vector<uint8_t> &r_out);

	Ref<FileAccess> file;
	String pack_path;
	uint64_t base_offset = 0; 
	gdpk::BuildKey bk;
	bool ready = false;
	uint16_t header_flags = 0;
	uint32_t chunk_size = gdpk::CHUNK_SIZE; 
	uint8_t tree_root[32] = {0};

	Vector<Entry> entries;
	HashMap<String, int> by_path;
};

class FileAccessGdpk : public FileAccess {
public:
	FileAccessGdpk(GdpkPackSource *p_src, int p_entry);

	virtual Error open_internal(const String &p_path, int p_mode_flags) override;
	virtual bool is_open() const override;
	virtual String get_path() const override;
	virtual String get_path_absolute() const override;

	virtual void seek(uint64_t p_position) override;
	virtual void seek_end(int64_t p_position = 0) override;
	virtual uint64_t get_position() const override;
	virtual uint64_t get_length() const override;
	virtual bool eof_reached() const override;

	virtual uint8_t get_8() const override;
	virtual uint64_t get_buffer(uint8_t *p_dst, uint64_t p_length) const override;

	virtual Error get_error() const override;
	virtual void flush() override;
	virtual void store_8(uint8_t p_dest) override;
	virtual void store_buffer(const uint8_t *p_src, uint64_t p_length) override;
	virtual bool file_exists(const String &p_name) override;
	virtual void close() override;

private:
	GdpkPackSource *src = nullptr;
	int entry_idx = -1;
	mutable uint64_t pos = 0; 
	uint64_t logical_len = 0; 
	mutable Error last_error = OK;

	mutable int cached_chunk = -1;
	mutable Vector<uint8_t> chunk_buf;
	mutable uint32_t chunk_len = 0;

	mutable Vector<uint8_t> mem;
	mutable bool mem_loaded = false;

	bool ensure_chunk(uint64_t chunk_index) const;
	bool ensure_mem() const;
};
