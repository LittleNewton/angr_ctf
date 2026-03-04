import angr
import sys
import claripy

# TODO: 如何计算 stack 布局


def solver():
    bin_path = './04_angr_symbolic_stack.elf'
    proj = angr.Project(bin_path)
    start_addr = 0x0804938f  # first insn after `call scanf`
    init_state = proj.factory.blank_state(addr=start_addr)

    # create symbolic variables
    password_0 = claripy.BVS('password_0', 32)  # 32-bit integer
    password_1 = claripy.BVS('password_1', 32)  # 32-bit integer

    # set the context
    init_state.regs.ebp = init_state.regs.esp
    # first val is on [ebp - 0xC], so we need to `sub esp` so that we can push properly
    init_state.regs.esp -= 0x8
    # these two variables are continuous on the stack
    init_state.stack_push(password_0)
    init_state.stack_push(password_1)
    # the relative position of esp when return from scanf()
    # seems that it's okay to not do it?
    init_state.regs.esp -= 12

    # now to solve!
    simgr = proj.factory.simgr(init_state)
    simgr.explore(find=0x080493e4, avoid=0x080493d2)

    if simgr.found:
        solution_state = simgr.found[0]
        solution_0 = solution_state.solver.eval(password_0)
        solution_1 = solution_state.solver.eval(password_1)

        print('password_0: {}'.format(solution_0))
        print('password_1: {}'.format(solution_1))
    else:
        raise Exception('Could not find the solution!')


if __name__ == "__main__":
    solver()
