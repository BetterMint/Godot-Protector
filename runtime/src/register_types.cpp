
#include "register_types.h"

#include <gdextension_interface.h>
#include <godot_cpp/classes/engine.hpp>
#include <godot_cpp/core/defs.hpp>
#include <godot_cpp/core/memory.hpp>
#include <godot_cpp/godot.hpp>

#include "gdpk.h"
#include "gvm_vm.h"

using namespace godot;

static Gdpk *gdpk_singleton = nullptr;

void initialize_gdpk_module(ModuleInitializationLevel p_level) {
	if (p_level != MODULE_INITIALIZATION_LEVEL_SCENE) return;

	GDREGISTER_CLASS(GvmVM);
	GDREGISTER_CLASS(Gdpk);

	gdpk_singleton = memnew(Gdpk);
	Engine::get_singleton()->register_singleton("Gdpk", gdpk_singleton);
}

void uninitialize_gdpk_module(ModuleInitializationLevel p_level) {
	if (p_level != MODULE_INITIALIZATION_LEVEL_SCENE) return;
	Engine::get_singleton()->unregister_singleton("Gdpk");
	if (gdpk_singleton) {
		memdelete(gdpk_singleton);
		gdpk_singleton = nullptr;
	}
}

extern "C" {

GDExtensionBool GDE_EXPORT gdpk_library_init(
		GDExtensionInterfaceGetProcAddress p_get_proc_address,
		const GDExtensionClassLibraryPtr p_library,
		GDExtensionInitialization *r_initialization) {
	GDExtensionBinding::InitObject init_obj(p_get_proc_address, p_library,
			r_initialization);
	init_obj.register_initializer(initialize_gdpk_module);
	init_obj.register_terminator(uninitialize_gdpk_module);
	init_obj.set_minimum_library_initialization_level(
			MODULE_INITIALIZATION_LEVEL_SCENE);
	return init_obj.init();
}
}
