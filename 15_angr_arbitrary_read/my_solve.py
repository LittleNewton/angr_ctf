import angr
import claripy

def solver():
    bin_path = './15_angr_arbitrary_read'
    proj = angr.Project(bin_path)

    class MySimScanfProcedure(angr.SimProcedure):
        def run(self, str, key_addr, chr_arr_addr):
            key_bvs = claripy.BVS('key', 4 * 8)
            chr_arr_bvs = claripy.BVS('chr_arr', 20 * 8)
            for ch in chr_arr_bvs.chop(bits = 8):
                self.state.add_constraints(ch >= '0', ch <= 'z')
            self.state.memory.store(key_addr, key_bvs,
                                    endness = proj.arch.memory_endness)
            self.state.memory.store(chr_arr_addr, chr_arr_bvs)
            self.state.globals['password_0'] = key_bvs
            self.state.globals['password_1'] = chr_arr_bvs

    proj.hook_symbol('__isoc99_scanf', MySimScanfProcedure())

    init_state = proj.factory.entry_state()
    simgr = proj.factory.simgr(init_state)

    def is_success(state):
        call_puts_addr = 0x8049090
        if state.addr != call_puts_addr:
            return False

        good_str_addr = 0x58465157
        puts_param = state.memory.load(state.regs.esp + 4, 4,
                                       endness = proj.arch.memory_endness)
        if state.solver.symbolic(puts_param):
            copy_state = state.copy()
            copy_state.add_constraints(puts_param == good_str_addr)
            if copy_state.satisfiable():
                state.add_constraints(puts_param == good_str_addr)
                return True
            else:
                return False
        else:
            return False

    simgr.explore(find = is_success)

    if simgr.found:
        solution_state = simgr.found[0]
        solution_0 = solution_state.solver.eval(solution_state.globals['password_0'])
        solution_1 = solution_state.solver.eval(solution_state.globals['password_1'],
                                                cast_to=bytes)

        print('password_0: {}'.format(solution_0))
        print('password_1: {}'.format(solution_1))
    else:
        raise Exception('Could not find the solution!')

if __name__ == "__main__":
    solver()