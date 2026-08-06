import json
from wasmtime import Engine, Store, Module, Linker, FuncType, ValType, Func, Memory, MemoryType, Limits

class OpaWasmEngine:
    def __init__(self, wasm_file):
        self.engine = Engine()
        self.store = Store(self.engine)
        self.module = Module.from_file(self.engine, wasm_file)
        
        self.linker = Linker(self.engine)
        
        i32 = ValType.i32()
        
        # OPA requires some env imports
        self.linker.define(self.store, "env", "opa_abort", Func(self.store, FuncType([i32], []), self._opa_abort))
        self.linker.define(self.store, "env", "opa_println", Func(self.store, FuncType([i32], []), self._opa_println))
        self.linker.define(self.store, "env", "opa_builtin0", Func(self.store, FuncType([i32, i32], [i32]), lambda *args: 0))
        self.linker.define(self.store, "env", "opa_builtin1", Func(self.store, FuncType([i32, i32, i32], [i32]), lambda *args: 0))
        self.linker.define(self.store, "env", "opa_builtin2", Func(self.store, FuncType([i32, i32, i32, i32], [i32]), lambda *args: 0))
        self.linker.define(self.store, "env", "opa_builtin3", Func(self.store, FuncType([i32, i32, i32, i32, i32], [i32]), lambda *args: 0))
        self.linker.define(self.store, "env", "opa_builtin4", Func(self.store, FuncType([i32, i32, i32, i32, i32, i32], [i32]), lambda *args: 0))
        
        
        self.memory = Memory(self.store, MemoryType(Limits(2, None)))
        self.linker.define(self.store, "env", "memory", self.memory)
        
        self.instance = self.linker.instantiate(self.store, self.module)
        
        self.opa_malloc = self.instance.exports(self.store)["opa_malloc"]
        self.opa_json_parse = self.instance.exports(self.store)["opa_json_parse"]
        self.opa_json_dump = self.instance.exports(self.store)["opa_json_dump"]
        
        self.opa_eval_ctx_new = self.instance.exports(self.store)["opa_eval_ctx_new"]
        self.opa_eval_ctx_set_input = self.instance.exports(self.store)["opa_eval_ctx_set_input"]
        self.opa_eval_ctx_set_entrypoint = self.instance.exports(self.store).get("opa_eval_ctx_set_entrypoint")
        self.eval_func = self.instance.exports(self.store)["eval"]
        self.opa_eval_ctx_get_result = self.instance.exports(self.store)["opa_eval_ctx_get_result"]

        # Parse entrypoints mapping
        self.entrypoints = {}
        if "entrypoints" in self.instance.exports(self.store):
            ep_func = self.instance.exports(self.store)["entrypoints"]
            ep_addr = ep_func(self.store)
            ep_dump_addr = self.opa_json_dump(self.store, ep_addr)
            ep_str = self._read_string(ep_dump_addr)
            if ep_str:
                self.entrypoints = json.loads(ep_str)


    def _opa_abort(self, addr):
        raise Exception(f"OPA Aborted")

    def _opa_println(self, addr):
        pass

    def _write_string(self, text: str) -> int:
        encoded = text.encode("utf-8")
        addr = self.opa_malloc(self.store, len(encoded))
        data = self.memory.data_ptr(self.store)
        import ctypes
        ptr = ctypes.cast(data, ctypes.c_void_p).value
        ctypes.memmove(ptr + addr, encoded, len(encoded))
        return addr, len(encoded)

    def _read_string(self, addr: int) -> str:
        data = self.memory.data_ptr(self.store)
        import ctypes
        ptr = ctypes.cast(data, ctypes.c_void_p).value
        mem = ctypes.string_at(ptr + addr)
        return mem.decode("utf-8")

    def evaluate(self, input_dict: dict, entrypoint_name: str = None) -> list:
        input_str = json.dumps(input_dict)
        addr, length = self._write_string(input_str)
        
        parsed_addr = self.opa_json_parse(self.store, addr, length)
        if parsed_addr == 0:
            raise Exception("Failed to parse input JSON")
            
        ctx = self.opa_eval_ctx_new(self.store)
        self.opa_eval_ctx_set_input(self.store, ctx, parsed_addr)
        
        if entrypoint_name and self.opa_eval_ctx_set_entrypoint:
            # entrypoint_name might be like "data.gasc.governor.integrity.allow_state_write"
            # OPA WASM entrypoints usually omit "data." and use slashes
            ep_key = entrypoint_name.replace("data.", "").replace(".", "/")
            if ep_key in self.entrypoints:
                self.opa_eval_ctx_set_entrypoint(self.store, ctx, self.entrypoints[ep_key])
            else:
                raise RuntimeError(
                    f"OPA WASM entrypoint not found: '{ep_key}'. "
                    f"Available: {list(self.entrypoints.keys())}"
                )
        
        self.eval_func(self.store, ctx)

        result_addr = self.opa_eval_ctx_get_result(self.store, ctx)
        
        dump_addr = self.opa_json_dump(self.store, result_addr)
        result_str = self._read_string(dump_addr)
        
        parsed = json.loads(result_str)
        # OPA WASM returns either a list of result sets or a bare value.
        # Normalize to always return a list for consistent caller handling.
        if isinstance(parsed, list):
            return parsed
        return [{"result": parsed}]
