import angr
import claripy

# filter to check satisfiability


def filter_func(state):
    print_good_addr = 0x58465168
    return state.satisfiable(extra_constraints=(state.regs.eip == print_good_addr, ))


def solver():
    bin_path = "./17_angr_arbitrary_jump.elf"
    proj = angr.Project(bin_path)

    # hook the scanf to symbolize our input
    class SimScanfProcedure(angr.SimProcedure):
        def run(self, fmtstr, input_addr):
            input_bvs = claripy.BVS('input_addr', 200 * 8)
            for chr in input_bvs.chop(bits=8):
                self.state.add_constraints(chr >= '0', chr <= 'z')
            self.state.memory.store(input_addr, input_bvs)
            self.state.globals['input_val'] = input_bvs

    proj.hook_symbol('__isoc99_scanf', SimScanfProcedure())

    # create simgr that can save unconstraints
    init_state = proj.factory.entry_state()
    simgr = proj.factory.simgr(
        init_state,
        save_unconstrained=True,  # 一定要打开这个选项，否则无法保存无约束状态
        stashes={
            'active': [init_state],
            'unconstrained': [],
            'found': [],
        }
    )

    # simulated execution by steps
    while not simgr.found:
        # no more states for execution
        if (not simgr.active) and (not simgr.unconstrained):
            break

        # check for unconstrained states
        simgr.move(
            from_stash='unconstrained',
            to_stash='found',
            filter_func=filter_func
        )

        # step to next basic block
        simgr.step()

    if simgr.found:
        print("[*] found {} solution state(s)".format(len(simgr.found)))
        solution_state = simgr.found[0]
        print_good_addr = 0x58465164  # 这是一个理论上不可能存在的跳转地址，因为我们的非法输入导致了 return 地址被覆盖。
        solution_state.add_constraints(solution_state.regs.eip == print_good_addr)
        input_val = solution_state.solver.eval(solution_state.globals['input_val'], cast_to=bytes)

        print('password: {}'.format(input_val))
    else:
        raise Exception('Could not find the solution!')


if __name__ == "__main__":
    solver()
