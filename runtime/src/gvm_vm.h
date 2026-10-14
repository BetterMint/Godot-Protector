
#pragma once

#include <godot_cpp/classes/ref_counted.hpp>
#include <godot_cpp/templates/hash_map.hpp>
#include <godot_cpp/templates/vector.hpp>
#include <godot_cpp/variant/array.hpp>
#include <godot_cpp/variant/callable.hpp>
#include <godot_cpp/variant/dictionary.hpp>
#include <godot_cpp/variant/packed_byte_array.hpp>
#include <godot_cpp/variant/string.hpp>
#include <godot_cpp/variant/string_name.hpp>
#include <godot_cpp/variant/variant.hpp>

namespace godot {

enum GvmOp : uint8_t {
	GVM_NOP = 0,
	GVM_LOADK, GVM_LOADI, GVM_MOVE,
	GVM_ADD, GVM_SUB, GVM_MUL, GVM_DIV, GVM_MOD,
	GVM_NEG, GVM_NOT, GVM_AND, GVM_OR,
	GVM_CMPEQ, GVM_CMPNE, GVM_CMPLT, GVM_CMPLE, GVM_CMPGT, GVM_CMPGE,
	GVM_JMP, GVM_JT, GVM_JF,
	GVM_PUSH, GVM_POP,
	GVM_CALL, GVM_CALLM,
	GVM_GETG, GVM_SETG, GVM_GETM, GVM_SETM,
	GVM_NEWARR, GVM_NEWDICT, GVM_AGET, GVM_ASET,
	GVM_ITER, GVM_RET, GVM_YIELD, GVM_SELF,
	GVM_OP_COUNT
};

class GvmVM : public RefCounted {
	GDCLASS(GvmVM, RefCounted);

public:
	struct Dialect {
		uint8_t encode_map[GVM_OP_COUNT];
		uint8_t decode_map[256]; 
		uint64_t salt = 0;
		void init(uint64_t p_salt);
		uint32_t cell_key(uint64_t cell) const;
		GvmOp decode_op(uint8_t byte) const { return (GvmOp)decode_map[byte]; }
	};

	struct Func {
		uint32_t entry_cell = 0;
		uint16_t arg_count = 0;
		uint16_t name_kx = 0;
	};

protected:
	static void _bind_methods();

public:
	GvmVM() = default;

	bool load_image(const PackedByteArray &image, String &r_err);
	bool is_loaded() const { return loaded; }

	Variant call_func(int func_idx, const Array &args);
	
	Variant resume(const Variant &feed);

	void set_host_call(const StringName &name, const Callable &cb) {
		host_calls[name] = cb;
	}
	void set_self(Object *obj) {
		self_v = obj ? Variant(obj) : Variant(); 
		member_init_ran = false; 
	}
	String get_error() const { return error; }
	Dictionary get_globals() const { return globals; }

	int func_count() const { return (int)funcs.size(); }
	String func_name(int func_idx) const;
	int func_index_by_name(const String &name) const;
	
	bool run_member_init();

private:
	struct Insn {
		uint8_t op = GVM_NOP;
		uint8_t a = 0;
		int32_t b = 0;
		int32_t c = 0; 
	};

	struct IterState {
		Variant iterable;   
		Variant iter;       
		bool valid = false; 
		uint32_t exit_cell = 0; 
		
	};

	struct Frame {
		Variant regs[16];
		Vector<Variant> stack;
		uint32_t pc = 0;
		
		HashMap<uint32_t, IterState> iters;
	};

	Dialect dialect;
	Vector<Variant> consts;
	Vector<Func> funcs;
	Vector<Insn> code;
	Dictionary globals;
	HashMap<StringName, Callable> host_calls;
	Variant self_v; 
	bool loaded = false;
	String error;

	int member_init_func = -1;
	bool member_init_ran = false;

	bool has_suspended = false;
	uint8_t yield_reg = 0; 
	Frame suspended;

	Variant run(Frame &f); 
	bool vm_fail(const String &msg);

	bool call_builtin_name(const StringName &name, const Array &argv,
			Variant &r_ret);
	
	void drop_abandoned_iters(Frame &f, uint32_t target);

	bool decode_cell(const uint8_t *code_bytes, size_t code_len, size_t &pos,
			uint64_t cell_index, Insn &out) const;
};

} 
