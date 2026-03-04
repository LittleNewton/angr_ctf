import angr
import claripy


def solver():
    # Load the shared library, not the main executable
    bin_path = './lib14_angr_shared_library.elf.so'
    base_addr = 0x400000
    proj = angr.Project(bin_path, load_options={
        'main_opts': {
            'base_addr': base_addr
        }
    })

    # validate(char* buffer, int length)
    # validate is at offset 0x1234 in the .so
    validate_addr = base_addr + 0x1234

    # Symbolic password buffer: 8 bytes
    password = claripy.BVS('password', 8 * 8)
    password_addr = 0x3000000
    buffer_pointer = claripy.BVV(password_addr, 32)

    # Use call_state to properly set up a cdecl function call
    init_state = proj.factory.call_state(
        validate_addr,
        buffer_pointer,
        claripy.BVV(8, 32)
    )
    init_state.memory.store(password_addr, password)

    simgr = proj.factory.simgr(init_state)

    # Find address just before ret where eax holds return value
    # 0x12dc: movzbl %al, %eax  (last instruction before leave/ret)
    check_addr = base_addr + 0x12dc
    simgr.explore(find=check_addr)

    if simgr.found:
        solution_state = simgr.found[0]
        solution_state.add_constraints(solution_state.regs.eax == 1)
        print(solution_state.solver.eval(password, cast_to=bytes))
    else:
        raise Exception('Could not find the solution')


if __name__ == '__main__':
    solver()
