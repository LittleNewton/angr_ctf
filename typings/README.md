# angr / claripy Type Stubs

Minimal hand-written `.pyi` stubs for **angr** and **claripy**, covering the
API actually used in this repo (lessons 00-14).  The goal is to silence the
most noisy type-checker warnings without misrepresenting the real API.

---

## Directory layout

```
typings/
├── README.md            ← this file
├── angr/
│   ├── __init__.pyi          re-exports Project, SimState, SimulationManager …
│   ├── project.pyi           angr.Project
│   ├── factory.pyi           AngrObjectFactory (proj.factory)
│   ├── sim_state.pyi         SimState
│   ├── sim_manager.pyi       SimulationManager
│   ├── sim_procedure.pyi     SimProcedure base class
│   ├── sim_file.pyi          SimFile
│   ├── options.pyi           angr.options.*
│   ├── _sim_procedures.pyi   SIM_PROCEDURES dict
│   └── state_plugins/
│       ├── __init__.pyi
│       ├── solver.pyi        state.solver  (SimSolver)
│       ├── memory.pyi        state.memory  (SimMemory)
│       ├── registers.pyi     state.regs    (SimRegNamespace)
│       ├── posix.pyi         state.posix   (SimSystemPosix)
│       └── filesystem.pyi    state.fs      (SimFilesystem)
└── claripy/
    ├── __init__.pyi          BVS, BVV, If, And, Or, …
    └── ast/
        ├── __init__.pyi
        ├── base.pyi          Base / Bool AST node
        └── bv.pyi            BV (bitvector) AST node
```

---

## Enabling the stubs

### Pyright / Pylance (VS Code)

The stubs are registered in `.vscode/settings.json`:

```json
"python.analysis.stubPath": "typings"
```

And in `pyrightconfig.json` at the repo root:

```json
{
  "typeCheckingMode": "basic",
  "pythonVersion": "3.12",
  "stubPath": "typings"
}
```

### mypy

Config is in `.mypy.ini` at the repo root:

```ini
[mypy]
python_version = 3.12
mypy_path = typings
ignore_missing_imports = True
```

Run from the repo root:

```bash
mypy 00_angr_find/my_solve.py
# or check all at once:
mypy $(find . -name 'my_solve*.py' | sort)
```

---

## Covered API (by file)

| Stub file | Symbols covered |
|-----------|----------------|
| `angr/__init__.pyi` | `Project`, `SimState`, `SimulationManager`, `SimProcedure`, `SimFile`, `options`, `SIM_PROCEDURES` |
| `angr/project.pyi` | `Project.__init__`, `.entry`, `.arch`, `.factory`, `.hook()`, `.hook_symbol()`, `.is_hooked()`, `.unhook()` |
| `angr/factory.pyi` | `.entry_state()`, `.blank_state()`, `.call_state()`, `.simgr()`, `.simulation_manager()` |
| `angr/sim_state.pyi` | `.regs`, `.memory`, `.solver`, `.posix`, `.fs`, `.arch`, `.globals`, `.stack_push()`, `.add_constraints()`, `.copy()` |
| `angr/sim_manager.pyi` | `.explore()`, `.step()`, `.run()`, `.move()`, `.found`, `.active`, `.avoided`, `.deadended`, `.errored` |
| `angr/sim_procedure.pyi` | `SimProcedure.run()`, `.state`, `.ret()`, `.exit()`, `.call()` |
| `angr/sim_file.pyi` | `SimFile.__init__` with `name`, `content`, `size` |
| `angr/options.pyi` | `SYMBOL_FILL_UNCONSTRAINED_MEMORY`, `SYMBOL_FILL_UNCONSTRAINED_REGISTERS` + common extras |
| `angr/_sim_procedures.pyi` | `SIM_PROCEDURES: Dict[str, Dict[str, Type[SimProcedure]]]` |
| `state_plugins/solver.pyi` | `.eval()` (overloaded for `cast_to=bytes/int`), `.min()`, `.max()`, `.add()`, `.satisfiable()`, `.BVS()`, `.BVV()` |
| `state_plugins/memory.pyi` | `.store()`, `.load()` with `endness` kwarg |
| `state_plugins/registers.pyi` | All common x86/x86-64 registers + `__getattr__` fallback |
| `state_plugins/posix.pyi` | `.dumps(fd)`, `.stdin`, `.stdout`, `.stderr` |
| `state_plugins/filesystem.pyi` | `.insert()`, `.get()`, `.delete()` |
| `claripy/__init__.pyi` | `BVS`, `BVV`, `BoolS`, `BoolV`, `If`, `And`, `Or`, `Not`, `Concat`, `Extract`, `ZeroExt`, `SignExt`, `LShR`, `ULT/ULE/UGT/UGE`, `SLT/SLE/SGT/SGE`, `true`, `false` |
| `claripy/ast/base.pyi` | `Base`, `Bool` with all operators |
| `claripy/ast/bv.pyi` | `BV` with `.zero_extend()`, `.sign_extend()`, `.chop()`, slice `[]` |

Entries marked **常见补充** in the stub comments are added for completeness
beyond what was directly observed in lessons 00-14.

---

## Incrementally extending the stubs

1. Find the warning in your editor / type-checker output, e.g.:
   `Cannot access member "loader" for type "Project"`.
2. Open the relevant `.pyi` file (e.g. `typings/angr/project.pyi`).
3. Add the missing attribute/method with the correct signature, or use
   `-> Any` if you are unsure.
4. Restart the Pylance language server (`> Python: Restart Language Server`).

If angr publishes official stubs in the future, delete `typings/angr/` and
`typings/claripy/` and rely on the upstream package.

---

## Known limitations

- `state.globals` is typed as `Dict[str, Any]` — subscript access is safe but
  values are untyped.
- `SimProcedure.run()` return type is `Any`; narrow it yourself if needed.
- `state.arch.memory_endness` resolves via the `Any`-typed `arch` attribute.
- `SimulationManager` stash access via `simgr['stash']` returns
  `List[SimState]`; direct attribute access (e.g. `simgr.active`) is also
  typed.
