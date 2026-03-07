import angr
import claripy

count_executions = 0


def solver():
    bin_path = "./16_angr_arbitrary_write.elf"
    proj = angr.Project(bin_path)

    # hook the scanf to symbolize our input
    class SimScanfProcedure(angr.SimProcedure):
        def run(self, fmtstr, key_addr, chr_arr_addr):
            key_bvs = claripy.BVS('key_bvs', 4 * 8)
            chr_arr_bvs = claripy.BVS('chr_arr_bvs', 20 * 8)
            for chr in chr_arr_bvs.chop(bits=8):
                self.state.add_constraints(chr >= '0', chr <= 'z')
            self.state.memory.store(key_addr, key_bvs, endness=proj.arch.memory_endness)
            self.state.memory.store(chr_arr_addr, chr_arr_bvs)
            self.state.globals['key_val'] = key_bvs
            self.state.globals['chr_arr_val'] = chr_arr_bvs

    proj.hook_symbol('__isoc99_scanf', SimScanfProcedure())

    def is_success(state):
        global count_executions
        count_executions += 1
        print(f">>> {count_executions} Checking state at address: {hex(state.addr)}")
        strncpy_plt = 0x08049070
        if state.addr != strncpy_plt:
            return False

        strncpy_param1 = state.memory.load(state.regs.esp + 4, 4,
                                           endness=proj.arch.memory_endness)
        strncpy_param2 = state.memory.load(state.regs.esp + 8, 4,
                                           endness=proj.arch.memory_endness)
        first_8_chr = state.memory.load(strncpy_param2, 8)
        password_buffer_addr = 0x5846514c

        if state.solver.symbolic(strncpy_param1) and state.solver.symbolic(first_8_chr):
            copy_state = state.copy()
            copy_state.add_constraints(strncpy_param1 == password_buffer_addr)
            copy_state.add_constraints(first_8_chr == b'UEQFKBEC')
            if copy_state.satisfiable():
                state.add_constraints(strncpy_param1 == password_buffer_addr)
                state.add_constraints(first_8_chr == b'UEQFKBEC')
                return True
            else:
                return False
        else:
            return False

    init_state = proj.factory.entry_state()
    simgr = proj.factory.simgr(init_state)
    simgr.explore(find=is_success)

    if simgr.found:
        solution_state = simgr.found[0]
        key_val = solution_state.solver.eval(solution_state.globals['key_val'])
        chr_arr_val = solution_state.solver.eval(solution_state.globals['chr_arr_val'],
                                                 cast_to=bytes)

        print('password_0: {}'.format(key_val))
        print('password_1: {}'.format(chr_arr_val))
    else:
        raise Exception('Could not find the solution!')


if __name__ == "__main__":
    solver()


"""
为什么副本可满足后，还要给原状态也加约束？

意思是：

“既然我已经确认：当前这个状态存在一种具体赋值，能够满足我要的条件；
那么我现在就把这种条件正式施加到原始状态上，把它收缩成一个真正满足目标条件的状态。”

所以这一步的意义是把“存在一个满足条件的解”变成“当前 state 就以这些条件为前提继续存在”。
"""
