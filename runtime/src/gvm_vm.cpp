
#include "gvm_vm.h"

#include <godot_cpp/classes/engine.hpp>
#include <godot_cpp/classes/object.hpp>
#include <godot_cpp/core/class_db.hpp>
#include <godot_cpp/templates/pair.hpp>
#include <godot_cpp/variant/string_name.hpp>
#include <godot_cpp/variant/utility_functions.hpp>
#include <cmath>
#include <cstring>

namespace godot {

namespace {

struct PyMT {
	uint32_t mt[624];
	int idx = 624; 

	static constexpr int N = 624, M = 397;
	static constexpr uint32_t MATRIX_A = 0x9908b0dfu;
	static constexpr uint32_t UPPER = 0x80000000u, LOWER = 0x7fffffffu;

	void genrand_init(uint32_t s) {
		mt[0] = s;
		for (int i = 1; i < N; i++)
			mt[i] = 1812433253u * (mt[i - 1] ^ (mt[i - 1] >> 30)) + i;
		idx = N;
	}

	void seed_key(const uint32_t *key, int keylen) {
		genrand_init(19650218u);
		int i = 1, j = 0;
		int k = N > keylen ? N : keylen;
		for (; k; k--) {
			mt[i] = (mt[i] ^ ((mt[i - 1] ^ (mt[i - 1] >> 30)) * 1664525u)) +
					key[j] + j;
			i++;
			j++;
			if (i >= N) { mt[0] = mt[N - 1]; i = 1; }
			if (j >= keylen) j = 0;
		}
		for (k = N - 1; k; k--) {
			mt[i] = (mt[i] ^ ((mt[i - 1] ^ (mt[i - 1] >> 30)) * 1566083941u)) - i;
			i++;
			if (i >= N) { mt[0] = mt[N - 1]; i = 1; }
		}
		mt[0] = 0x80000000u;
	}

	void seed_u64(uint64_t v) {
		uint32_t key[2];
		int n;
		if (v == 0) {
			key[0] = 0; n = 1;
		} else if (v >> 32) {
			key[0] = (uint32_t)v; key[1] = (uint32_t)(v >> 32); n = 2;
		} else {
			key[0] = (uint32_t)v; n = 1;
		}
		seed_key(key, n);
	}

	uint32_t next_u32() {
		if (idx >= N) { 
			uint32_t y;
			int kk;
			for (kk = 0; kk < N - M; kk++) {
				y = (mt[kk] & UPPER) | (mt[kk + 1] & LOWER);
				mt[kk] = mt[kk + M] ^ (y >> 1) ^ (y & 1 ? MATRIX_A : 0);
			}
			for (; kk < N - 1; kk++) {
				y = (mt[kk] & UPPER) | (mt[kk + 1] & LOWER);
				mt[kk] = mt[kk + (M - N)] ^ (y >> 1) ^ (y & 1 ? MATRIX_A : 0);
			}
			y = (mt[N - 1] & UPPER) | (mt[0] & LOWER);
			mt[N - 1] = mt[M - 1] ^ (y >> 1) ^ (y & 1 ? MATRIX_A : 0);
			idx = 0;
		}
		uint32_t y = mt[idx++];
		y ^= y >> 11;
		y ^= (y << 7) & 0x9d2c5680u;
		y ^= (y << 15) & 0xefc60000u;
		y ^= y >> 18;
		return y;
	}

	uint32_t getrandbits(int k) { return next_u32() >> (32 - k); }

	uint32_t randbelow(uint32_t n) {
		int k = 0;
		for (uint32_t t = n; t; t >>= 1) k++;
		uint32_t r;
		do { r = getrandbits(k); } while (r >= n);
		return r;
	}

	void shuffle(uint8_t *x, int n) {
		for (int i = n - 1; i > 0; i--) {
			uint32_t j = randbelow((uint32_t)i + 1);
			uint8_t t = x[i]; x[i] = x[j]; x[j] = t;
		}
	}
};

inline uint32_t feistel_f(uint32_t r, uint32_t key, uint32_t i) {
	uint32_t t = r * 0x9E37u + key + i * 0x85EBu;
	return (t >> 8) | ((t & 0xFFu) << 24); 
}

uint32_t feistel(uint32_t v, uint32_t key) {
	uint32_t l = v >> 16, r = v & 0xFFFFu;
	for (uint32_t i = 0; i < 4; i++) {
		uint32_t f = feistel_f(r, key, i);
		uint32_t nl = r, nr = l ^ (f & 0xFFFFu);
		l = nl; r = nr;
	}
	return (l << 16) | r;
}

uint32_t unfeistel(uint32_t v, uint32_t key) {
	uint32_t l = v >> 16, r = v & 0xFFFFu;
	for (int i = 3; i >= 0; i--) {
		uint32_t f = feistel_f(l, key, (uint32_t)i);
		uint32_t nl = r ^ (f & 0xFFFFu), nr = l;
		l = nl; r = nr;
	}
	return (l << 16) | r;
}

inline uint32_t rd_u16le(const uint8_t *p) { return p[0] | (p[1] << 8); }
inline uint32_t rd_u32le(const uint8_t *p) {
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
			((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
inline uint64_t rd_u64le(const uint8_t *p) {
	uint64_t v = 0;
	for (int i = 0; i < 8; i++) v |= (uint64_t)p[i] << (8 * i);
	return v;
}
inline int64_t rd_i64le(const uint8_t *p) { return (int64_t)rd_u64le(p); }
inline double rd_f64le(const uint8_t *p) {
	uint64_t u = rd_u64le(p);
	double d;
	memcpy(&d, &u, 8);
	return d;
}

} 

void GvmVM::Dialect::init(uint64_t p_salt) {
	salt = p_salt;
	PyMT rng;
	rng.seed_u64(salt ^ 0x47564D31ULL); 
	for (int i = 0; i < GVM_OP_COUNT; i++) encode_map[i] = (uint8_t)i;
	rng.shuffle(encode_map, GVM_OP_COUNT);
	memset(decode_map, 0, sizeof(decode_map));
	for (int sem = 0; sem < GVM_OP_COUNT; sem++)
		decode_map[encode_map[sem]] = (uint8_t)sem;
}

uint32_t GvmVM::Dialect::cell_key(uint64_t cell) const {
	
	uint64_t x = salt + cell * 0x9E3779B97F4A7C15ULL;
	x ^= x >> 30;
	x *= 0xBF58476D1CE4E5B9ULL;
	x ^= x >> 27;
	return (uint32_t)((x * 0x94D049BB133111EBULL) & 0xFFFFFFFFULL);
}

void GvmVM::_bind_methods() {
	
	ClassDB::bind_method(D_METHOD("is_loaded"), &GvmVM::is_loaded);
	ClassDB::bind_method(D_METHOD("get_error"), &GvmVM::get_error);
	ClassDB::bind_method(D_METHOD("call_func", "func_idx", "args"), &GvmVM::call_func);
	ClassDB::bind_method(D_METHOD("resume", "feed"), &GvmVM::resume);
	ClassDB::bind_method(D_METHOD("func_count"), &GvmVM::func_count);
	ClassDB::bind_method(D_METHOD("func_index_by_name", "name"),
			&GvmVM::func_index_by_name);
	ClassDB::bind_method(D_METHOD("run_member_init"), &GvmVM::run_member_init);
}

bool GvmVM::load_image(const PackedByteArray &image, String &r_err) {
	const uint8_t *d = image.ptr();
	size_t n = image.size();
	auto bad = [&](const char *m) { r_err = m; return false; };

	if (n < 28 || memcmp(d, "GVMB", 4) != 0) return bad("bad GVMB magic");
	if (rd_u32le(d + 4) != 1) return bad("unsupported GVMB version");
	uint64_t salt = rd_u64le(d + 8);
	uint32_t nconst = rd_u32le(d + 16);
	
	uint32_t code_len = rd_u32le(d + 20);
	uint32_t nfuncs = rd_u32le(d + 24);
	size_t pos = 28;

	consts.clear();
	consts.resize(nconst);
	for (uint32_t i = 0; i < nconst; i++) {
		if (pos >= n) return bad("const pool truncated");
		uint8_t tag = d[pos++];
		switch (tag) {
			case 0: consts[i] = Variant(); break;
			case 1: {
				if (pos + 1 > n) return bad("const bool truncated");
				consts[i] = (d[pos++] != 0);
				break;
			}
			case 2: {
				if (pos + 8 > n) return bad("const i64 truncated");
				consts[i] = rd_i64le(d + pos); pos += 8;
				break;
			}
			case 3: {
				if (pos + 8 > n) return bad("const f64 truncated");
				consts[i] = rd_f64le(d + pos); pos += 8;
				break;
			}
			case 4: {
				if (pos + 4 > n) return bad("const str truncated");
				uint32_t sl = rd_u32le(d + pos); pos += 4;
				if (pos + sl > n) return bad("const str truncated");
				consts[i] = String::utf8((const char *)d + pos, (int)sl);
				pos += sl;
				break;
			}
			case 5: {
				if (pos + 4 > n) return bad("const bytes truncated");
				uint32_t bl = rd_u32le(d + pos); pos += 4;
				if (pos + bl > n) return bad("const bytes truncated");
				PackedByteArray pba;
				pba.resize(bl);
				memcpy(pba.ptrw(), d + pos, bl);
				consts[i] = pba;
				pos += bl;
				break;
			}
			default: return bad("unknown const tag");
		}
	}

	funcs.clear();
	funcs.resize(nfuncs);
	for (uint32_t i = 0; i < nfuncs; i++) {
		if (pos + 8 > n) return bad("func table truncated");
		funcs[i].entry_cell = rd_u32le(d + pos);
		funcs[i].arg_count = rd_u16le(d + pos + 4);
		funcs[i].name_kx = rd_u16le(d + pos + 6);
		pos += 8;
	}

	if (pos + code_len > n) return bad("code truncated");
	dialect.init(salt);
	code.clear();
	size_t cp = pos;
	const size_t code_end = pos + code_len;
	while (cp < code_end) {
		Insn insn;
		if (!decode_cell(d, code_end, cp, (uint64_t)code.size(), insn))
			return bad("code decode error — malformed cell stream");
		code.push_back(insn);
	}
	for (const Func &fn : funcs)
		if (fn.entry_cell >= (uint32_t)code.size())
			return bad("func entry cell OOB");

	member_init_func = -1;
	member_init_ran = false;
	if (nfuncs > 0 && func_name(0) == "__gvm_member_init")
		member_init_func = 0;

	loaded = true;
	has_suspended = false;
	error = String();
	return true;
}

bool GvmVM::decode_cell(const uint8_t *c, size_t len, size_t &pos,
		uint64_t cell, Insn &out) const {
	if (pos >= len) return false;
	uint8_t enc = c[pos++];
	
	if (enc >= GVM_OP_COUNT) return false;
	out.op = dialect.decode_op(enc);
	uint32_t ck = dialect.cell_key(cell);

	switch (out.op) {
		
		case GVM_ADD: case GVM_SUB: case GVM_MUL: case GVM_DIV: case GVM_MOD:
		case GVM_AND: case GVM_OR:
		case GVM_CMPEQ: case GVM_CMPNE: case GVM_CMPLT: case GVM_CMPLE:
		case GVM_CMPGT: case GVM_CMPGE:
		case GVM_AGET: case GVM_ASET: case GVM_SETM: {
			if (pos + 2 > len) return false;
			uint8_t nib = c[pos++];
			out.a = nib >> 4;
			out.b = nib & 0xF;
			out.c = c[pos++];
			
			if (out.op != GVM_SETM && out.c >= 16) return false;
			break;
		}
		
		case GVM_MOVE: case GVM_NOT: case GVM_GETM: case GVM_CALLM:
		case GVM_ITER: {
			if (pos + 3 > len) return false;
			uint8_t nib = c[pos++];
			out.a = nib >> 4;
			out.b = nib & 0xF;
			out.c = rd_u16le(c + pos);
			pos += 2;
			break;
		}
		
		case GVM_LOADK: case GVM_CALL: case GVM_GETG: case GVM_SETG: {
			if (pos + 3 > len) return false;
			out.a = c[pos++];
			out.b = (int32_t)rd_u16le(c + pos);
			pos += 2;
			break;
		}
		
		case GVM_LOADI: {
			if (pos + 5 > len) return false;
			out.a = c[pos++];
			uint32_t raw = rd_u32le(c + pos);
			pos += 4;
			out.b = (int32_t)unfeistel(raw, ck); 
			break;
		}
		
		case GVM_JMP: case GVM_JT: case GVM_JF: {
			if (pos + 5 > len) return false;
			out.a = c[pos++];
			out.b = (int32_t)(rd_u32le(c + pos) ^ ck);
			pos += 4;
			break;
		}
		
		default: {
			if (pos + 1 > len) return false;
			out.a = c[pos++];
			break;
		}
	}
	return true;
}

namespace {

const char *op_name(uint8_t op) {
	static const char *names[] = {
		"NOP","LOADK","LOADI","MOVE","ADD","SUB","MUL","DIV","MOD","NEG",
		"NOT","AND","OR","CMPEQ","CMPNE","CMPLT","CMPLE","CMPGT","CMPGE",
		"JMP","JT","JF","PUSH","POP","CALL","CALLM","GETG","SETG","GETM",
		"SETM","NEWARR","NEWDICT","AGET","ASET","ITER","RET","YIELD","SELF"};
	return names[op < GVM_OP_COUNT ? op : 0];
}

bool is_num(const Variant &v) {
	return v.get_type() == Variant::INT || v.get_type() == Variant::FLOAT;
}

bool v_arith(uint8_t op, const Variant &a, const Variant &b, Variant &r,
		String &err) {
	Variant::Type ta = a.get_type(), tb = b.get_type();
	if (is_num(a) && is_num(b)) {
		bool fl = ta == Variant::FLOAT || tb == Variant::FLOAT;
		if (fl) {
			double x = a, y = b;
			switch (op) {
				case GVM_ADD: r = x + y; break;
				case GVM_SUB: r = x - y; break;
				case GVM_MUL: r = x * y; break;
				case GVM_DIV:
					if (y == 0.0) { err = "division by zero"; return false; }
					r = x / y; break;
				case GVM_MOD:
					if (y == 0.0) { err = "modulo by zero"; return false; }
					r = std::fmod(x, y); break;
			}
		} else {
			int64_t x = a, y = b;
			switch (op) {
				case GVM_ADD: r = x + y; break;
				case GVM_SUB: r = x - y; break;
				case GVM_MUL: r = x * y; break;
				case GVM_DIV:
					if (y == 0) { err = "integer division by zero"; return false; }
					r = x / y; break; 
				case GVM_MOD:
					if (y == 0) { err = "integer modulo by zero"; return false; }
					r = x % y; break;
			}
		}
		return true;
	}
	if (ta == Variant::STRING && tb == Variant::STRING && op == GVM_ADD) {
		r = (String)a + (String)b;
		return true;
	}
	
	auto vec_op = [&](auto va, const Variant &vb, Variant::Type vt,
			Variant &out) -> bool {
		if (vb.get_type() == vt) {
			decltype(va) w = vb; 
			switch (op) {
				case GVM_ADD: out = va + w; return true;
				case GVM_SUB: out = va - w; return true;
				case GVM_MUL: out = va * w; return true;
				case GVM_DIV: out = va / w; return true;
				default: return false;
			}
		}
		if (is_num(vb)) {
			double s = vb;
			if (op == GVM_MUL) { out = va * s; return true; }
			if (op == GVM_DIV) { out = va / s; return true; }
		}
		return false;
	};
	if (ta == Variant::VECTOR2) {
		if (vec_op((Vector2)a, b, Variant::VECTOR2, r)) return true;
	}
	if (ta == Variant::VECTOR3) {
		if (vec_op((Vector3)a, b, Variant::VECTOR3, r)) return true;
	}
	
	Variant::Operator eop;
	switch (op) {
		case GVM_ADD: eop = Variant::OP_ADD; break;
		case GVM_SUB: eop = Variant::OP_SUBTRACT; break;
		case GVM_MUL: eop = Variant::OP_MULTIPLY; break;
		case GVM_DIV: eop = Variant::OP_DIVIDE; break;
		case GVM_MOD: eop = Variant::OP_MODULE; break;
		default: eop = Variant::OP_MAX; break;
	}
	bool valid = false;
	Variant::evaluate(eop, a, b, r, valid);
	if (valid) return true;
	err = String("unsupported operand types for ") + op_name(op) + ": " +
			Variant::get_type_name(ta) + ", " + Variant::get_type_name(tb);
	return false;
}

bool v_neg(const Variant &a, Variant &r, String &err) {
	switch (a.get_type()) {
		case Variant::INT: r = -(int64_t)a; return true;
		case Variant::FLOAT: r = -(double)a; return true;
		case Variant::VECTOR2: r = -(Vector2)a; return true;
		case Variant::VECTOR3: r = -(Vector3)a; return true;
		default: {
			bool valid = false;
			Variant::evaluate(Variant::OP_NEGATE, a, Variant(), r, valid);
			if (valid) return true;
			err = "NEG on " + Variant::get_type_name(a.get_type());
			return false;
		}
	}
}

bool v_cmp(uint8_t op, const Variant &a, const Variant &b, bool &r,
		String &err) {
	if (is_num(a) && is_num(b)) {
		double x = a, y = b;
		switch (op) {
			case GVM_CMPEQ: r = x == y; break;
			case GVM_CMPNE: r = x != y; break;
			case GVM_CMPLT: r = x < y; break;
			case GVM_CMPLE: r = x <= y; break;
			case GVM_CMPGT: r = x > y; break;
			case GVM_CMPGE: r = x >= y; break;
		}
		return true;
	}
	if (a.get_type() == Variant::STRING && b.get_type() == Variant::STRING) {
		String x = a, y = b;
		switch (op) {
			case GVM_CMPEQ: r = x == y; break;
			case GVM_CMPNE: r = x != y; break;
			case GVM_CMPLT: r = x < y; break;
			case GVM_CMPLE: r = x <= y; break;
			case GVM_CMPGT: r = x > y; break;
			case GVM_CMPGE: r = x >= y; break;
		}
		return true;
	}
	if (a.get_type() == b.get_type() &&
			(op == GVM_CMPEQ || op == GVM_CMPNE)) {
		bool eq = (a == b); 
		r = (op == GVM_CMPEQ) ? eq : !eq;
		return true;
	}
	
	Variant::Operator eop;
	switch (op) {
		case GVM_CMPEQ: eop = Variant::OP_EQUAL; break;
		case GVM_CMPNE: eop = Variant::OP_NOT_EQUAL; break;
		case GVM_CMPLT: eop = Variant::OP_LESS; break;
		case GVM_CMPLE: eop = Variant::OP_LESS_EQUAL; break;
		case GVM_CMPGT: eop = Variant::OP_GREATER; break;
		case GVM_CMPGE: eop = Variant::OP_GREATER_EQUAL; break;
		default: eop = Variant::OP_MAX; break;
	}
	Variant out;
	bool valid = false;
	Variant::evaluate(eop, a, b, out, valid);
	if (valid) { r = truthy(out); return true; }
	err = String("unsupported comparison ") + op_name(op) + ": " +
			Variant::get_type_name(a.get_type()) + ", " +
			Variant::get_type_name(b.get_type());
	return false;
}

inline bool truthy(const Variant &v) { return v.booleanize(); }

Variant call_utility(const StringName &name, const Array &argv, bool &ok) {
	if (!Variant::has_utility_function(name)) { ok = false; return Variant(); }
	Vector<Variant> av;
	av.resize(argv.size());
	Vector<const Variant *> argp;
	argp.resize(argv.size());
	for (int i = 0; i < argv.size(); i++) {
		av[i] = argv[i];
		argp[i] = &av[i];
	}
	Variant ret;
	GDExtensionCallError cerr;
	
	Variant::call_utility_function(name, &ret, argp.ptrw(), (int)av.size(),
			cerr);
	ok = cerr.error == GDEXTENSION_CALL_OK;
	return ret;
}

bool builtin_fallback(const StringName &name, const Array &argv,
		Variant &r_ret) {
	String n = String(name);
	if (n == "bnot") {
		r_ret = ~(int64_t)(argv.size() ? argv[0] : Variant(0));
		return true;
	}
	if (n == "band" || n == "bor" || n == "bxor" || n == "bshl" ||
			n == "bshr") {
		if (argv.size() < 2) return false;
		int64_t x = argv[0], y = argv[1];
		if (n == "band") r_ret = x & y;
		else if (n == "bor") r_ret = x | y;
		else if (n == "bxor") r_ret = x ^ y;
		else if (n == "bshl") r_ret = x << (y & 63);
		else r_ret = x >> (y & 63);
		return true;
	}
	
	static const struct { const char *name; Variant::Type type; }
	CTOR_TYPES[] = {
		{ "Vector2", Variant::VECTOR2 }, { "Vector2i", Variant::VECTOR2I },
		{ "Vector3", Variant::VECTOR3 }, { "Vector3i", Variant::VECTOR3I },
		{ "Vector4", Variant::VECTOR4 }, { "Vector4i", Variant::VECTOR4I },
		{ "Color", Variant::COLOR }, { "Rect2", Variant::RECT2 },
		{ "Rect2i", Variant::RECT2I }, { "Transform2D", Variant::TRANSFORM2D },
		{ "StringName", Variant::STRING_NAME },
		{ "NodePath", Variant::NODE_PATH }, { "Plane", Variant::PLANE },
		{ "Quaternion", Variant::QUATERNION }, { "AABB", Variant::AABB },
		{ "Basis", Variant::BASIS }, { "Transform3D", Variant::TRANSFORM3D },
		{ "Projection", Variant::PROJECTION },
	};
	Variant::Type t = Variant::NIL;
	for (const auto &c : CTOR_TYPES)
		if (name == StringName(c.name)) { t = c.type; break; }
	if (t == Variant::NIL) return false;
	Vector<Variant> av;
	av.resize(argv.size());
	Vector<const Variant *> argp;
	argp.resize(argv.size());
	for (int i = 0; i < argv.size(); i++) {
		av[i] = argv[i];
		argp[i] = &av[i];
	}
	Callable::CallError cerr;
	Variant::construct(t, r_ret, argp.ptrw(), (int)av.size(), cerr);
	return cerr.error == Callable::CallError::CALL_OK;
}

} 

bool GvmVM::vm_fail(const String &msg) {
	error = msg;
	UtilityFunctions::push_error("GvmVM: " + msg);
	return false;
}

bool GvmVM::call_builtin_name(const StringName &name, const Array &argv,
		Variant &r_ret) {
	bool ok = false;
	Variant ret = call_utility(name, argv, ok);
	if (ok) { r_ret = ret; return true; }
	return builtin_fallback(name, argv, r_ret);
}

String GvmVM::func_name(int func_idx) const {
	if (func_idx < 0 || func_idx >= (int)funcs.size()) return String();
	uint16_t kx = funcs[func_idx].name_kx;
	if ((int)kx < (int)consts.size() &&
			consts[kx].get_type() == Variant::STRING)
		return (String)consts[kx];
	return String();
}

int GvmVM::func_index_by_name(const String &name) const {
	for (int i = 0; i < (int)funcs.size(); i++)
		if (func_name(i) == name) return i;
	return -1;
}

bool GvmVM::run_member_init() {
	if (member_init_func < 0) return true; 
	if (member_init_ran) return true;
	member_init_ran = true;                
	Frame f;
	f.pc = funcs[member_init_func].entry_cell;
	error = String();
	run(f);
	return error.is_empty();
}

Variant GvmVM::call_func(int func_idx, const Array &args) {
	if (!loaded) { vm_fail("no image loaded"); return Variant(); }
	if (func_idx < 0 || func_idx >= funcs.size()) {
		vm_fail("func index out of range");
		return Variant();
	}
	
	if (member_init_func >= 0 && !member_init_ran) {
		if (func_idx == member_init_func)
			member_init_ran = true;
		else
			run_member_init();
	}
	Frame f;
	f.pc = funcs[func_idx].entry_cell;
	
	int n = (int)funcs[func_idx].arg_count;
	if (args.size() < n) n = args.size();
	for (int i = 0; i < n && i + 1 < 16; i++) f.regs[i + 1] = args[i];
	return run(f);
}

void GvmVM::drop_abandoned_iters(Frame &f, uint32_t target) {
	
	Vector<uint32_t> dead;
	for (const KeyValue<uint32_t, IterState> &kv : f.iters)
		if (target < kv.key || target >= kv.value.exit_cell)
			dead.push_back(kv.key);
	for (uint32_t k : dead) f.iters.erase(k);
}

Variant GvmVM::resume(const Variant &feed) {
	if (!has_suspended) { vm_fail("nothing suspended"); return Variant(); }
	Frame f = suspended;
	has_suspended = false;
	f.regs[yield_reg] = feed; 
	return run(f);
}

Variant GvmVM::run(Frame &f) {
	auto failv = [&](const String &m) -> Variant {
		vm_fail(m);
		return Variant();
	};
	
	uint64_t steps = 0;
	const uint64_t STEP_LIMIT = 50000000;
	while (true) {
		if (++steps > STEP_LIMIT)
			return failv("step limit exceeded — image would not terminate");
		if (f.pc >= (uint32_t)code.size())
			return failv("pc ran off the code span (missing RET)");
		const uint32_t cell = f.pc;
		const Insn &in = code[f.pc];
		f.pc++; 
		
		if (in.op != GVM_JMP && in.a >= 16)
			return failv("register index out of range");

		switch (in.op) {
			case GVM_NOP: break;
			case GVM_LOADK:
				if (in.b < 0 || in.b >= consts.size())
					return failv("LOADK const index OOB");
				f.regs[in.a] = consts[in.b];
				break;
			case GVM_LOADI: f.regs[in.a] = (int64_t)in.b; break;
			case GVM_MOVE: f.regs[in.a] = f.regs[in.b]; break;

			case GVM_ADD: case GVM_SUB: case GVM_MUL: case GVM_DIV:
			case GVM_MOD: {
				String err;
				if (!v_arith(in.op, f.regs[in.b], f.regs[in.c], f.regs[in.a], err))
					return failv(err);
				break;
			}
			case GVM_NEG: {
				String err; 
				if (!v_neg(f.regs[in.a], f.regs[in.a], err)) return failv(err);
				break;
			}
			case GVM_NOT: f.regs[in.a] = !truthy(f.regs[in.b]); break;
			case GVM_AND:
				f.regs[in.a] = truthy(f.regs[in.b]) && truthy(f.regs[in.c]);
				break;
			case GVM_OR:
				f.regs[in.a] = truthy(f.regs[in.b]) || truthy(f.regs[in.c]);
				break;

			case GVM_CMPEQ: case GVM_CMPNE: case GVM_CMPLT: case GVM_CMPLE:
			case GVM_CMPGT: case GVM_CMPGE: {
				bool res; String err;
				if (!v_cmp(in.op, f.regs[in.b], f.regs[in.c], res, err))
					return failv(err);
				f.regs[in.a] = res;
				break;
			}

			case GVM_JMP: {
				uint32_t t = (uint32_t)in.b;
				drop_abandoned_iters(f, t);
				f.pc = t;
				break;
			}
			case GVM_JT:
				if (truthy(f.regs[in.a])) {
					uint32_t t = (uint32_t)in.b;
					drop_abandoned_iters(f, t);
					f.pc = t;
				}
				break;
			case GVM_JF:
				if (!truthy(f.regs[in.a])) {
					uint32_t t = (uint32_t)in.b;
					drop_abandoned_iters(f, t);
					f.pc = t;
				}
				break;

			case GVM_PUSH: f.stack.push_back(f.regs[in.a]); break;
			case GVM_POP:
				
				if (f.stack.is_empty()) { f.regs[in.a] = Variant(); break; }
				f.regs[in.a] = f.stack[f.stack.size() - 1];
				f.stack.remove_at(f.stack.size() - 1);
				break;

			case GVM_CALL: case GVM_CALLM: {
				
				uint32_t kx = (in.op == GVM_CALL) ? (uint32_t)in.b
						: (uint32_t)in.c;
				StringName callee;
				if (kx < (uint32_t)consts.size() &&
						consts[kx].get_type() == Variant::STRING)
					callee = StringName((String)consts[kx]);

				int argc = 0;
				if (!f.stack.is_empty()) {
					Variant top = f.stack[f.stack.size() - 1];
					f.stack.remove_at(f.stack.size() - 1);
					if (top.get_type() == Variant::INT)
						argc = (int)(int64_t)top;
				}
				if (argc > 255) argc = 255; 
				if (f.stack.size() < argc)
					return failv("call: stack underflow for argc");
				Array argv;
				argv.resize(argc);
				for (int i = argc - 1; i >= 0; i--) {
					argv[i] = f.stack[f.stack.size() - 1];
					f.stack.remove_at(f.stack.size() - 1);
				}

				if (in.op == GVM_CALL) {
					
					const Callable *cb = host_calls.getptr(callee);
					if (cb) { f.regs[in.a] = cb->callv(argv); break; }
					Variant ret;
					if (call_builtin_name(callee, argv, ret)) {
						f.regs[in.a] = ret;
						break;
					}
					return failv("CALL: no host/utility fn for '" +
							String(callee) + "'");
				}
				
				Callable bound(f.regs[in.b], callee);
				f.regs[in.a] = bound.callv(argv);
				break;
			}

			case GVM_GETG: {
				if (in.b < 0 || in.b >= consts.size())
					return failv("GETG const OOB");
				const Variant &key = consts[in.b];
				if (globals.has(key)) {
					f.regs[in.a] = globals[key];
					break;
				}
				f.regs[in.a] = Variant();
				if (key.get_type() != Variant::STRING) break;
				StringName kname = StringName((String)key);
				
				if (self_v.get_type() == Variant::OBJECT) {
					bool valid = false;
					f.regs[in.a] = self_v.get_named(kname, valid);
					if (valid) break;
					f.regs[in.a] = Variant();
				}
				Object *sing = Engine::get_singleton()->get_singleton_object(
						kname);
				if (sing) f.regs[in.a] = Variant(sing);
				break;
			}
			case GVM_SETG:
				if (in.b < 0 || in.b >= consts.size())
					return failv("SETG const OOB");
				globals[consts[in.b]] = f.regs[in.a];
				break;

			case GVM_GETM: {
				if (in.c < 0 || in.c >= consts.size() ||
						consts[in.c].get_type() != Variant::STRING)
					return failv("GETM: const is not a member name");
				bool valid = false;
				
				f.regs[in.a] = f.regs[in.b].get_named(
						StringName((String)consts[in.c]), valid);
				if (!valid) return failv("GETM: no such member");
				break;
			}
			case GVM_SETM: {
				if (in.c < 0 || in.c >= consts.size() ||
						consts[in.c].get_type() != Variant::STRING)
					return failv("SETM: const is not a member name");
				bool valid = false;
				f.regs[in.b].set_named(StringName((String)consts[in.c]),
						f.regs[in.a], valid);
				if (!valid) return failv("SETM: no such member");
				break;
			}

			case GVM_NEWARR: f.regs[in.a] = Array(); break;
			case GVM_NEWDICT: f.regs[in.a] = Dictionary(); break;

			case GVM_AGET: {
				bool valid = false;
				f.regs[in.a] = f.regs[in.b].get(f.regs[in.c], &valid);
				if (!valid) return failv("AGET: bad index/key");
				break;
			}
			case GVM_ASET: {
				bool valid = false;
				f.regs[in.b].set(f.regs[in.c], f.regs[in.a], &valid);
				if (!valid) return failv("ASET: bad index/key");
				break;
			}

			case GVM_ITER: {
				
				IterState &st = f.iters[cell];
				bool ok = false;
				if (!st.valid) {
					st.iterable = f.regs[in.b];
					st.exit_cell = (uint32_t)in.c;
					st.valid = st.iterable.iter_init(st.iter, ok) && ok;
					if (!st.valid) { f.pc = (uint32_t)in.c; break; }
				} else {
					ok = false;
					st.valid = st.iterable.iter_next(st.iter, ok) && ok;
					if (!st.valid) { f.pc = (uint32_t)in.c; break; }
				}
				ok = false;
				f.regs[in.a] = st.iterable.iter_get(st.iter, ok);
				if (!ok) f.regs[in.a] = Variant();
				break;
			}

			case GVM_RET: return f.regs[in.a];

			case GVM_YIELD: {
				
				suspended = f;
				yield_reg = in.a;
				has_suspended = true;
				Dictionary d;
				d["_gvm_yield"] = true;
				d["value"] = f.regs[in.a];
				return d;
			}
			case GVM_SELF:
				f.regs[in.a] = self_v;
				break;
			default: return failv(String("unhandled op ") + String::num_int64(in.op));
		}
	}
}

} 
