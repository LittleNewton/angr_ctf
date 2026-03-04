import angr
import claripy
import sys

# call __isoc99_scanf
# angr 做的是：
# 识别这个地址被 hook
# 不执行真实机器码
# 调用你的 MyScanfProcedure.run(...)
# 当 run() 结束时
# 按照当前 calling convention 构造一个 return 行为


class ScanfSimProcedure(angr.SimProcedure):
    def run(self, fmt_str, buffer0_addr, buffer1_addr):
        buffer0 = claripy.BVS("buffer0", 32)
        buffer1 = claripy.BVS("buffer1", 32)

        self.state.memory.store(buffer0_addr, buffer0)
        self.state.memory.store(buffer1_addr, buffer1)
        self.state.globals["buffer0"] = buffer0
        self.state.globals["buffer1"] = buffer1


def find_path(state):
    return b'Good Job.' in state.posix.dumps(sys.stdout.fileno())


def avoid_path(state):
    return b'Try again.' in state.posix.dumps(sys.stdout.fileno())


bin_path = './11_angr_sim_scanf.elf'
proj = angr.Project(bin_path)

proj.hook_symbol('__isoc99_scanf', ScanfSimProcedure())

init_state = proj.factory.entry_state()
simgr = proj.factory.simulation_manager(init_state)
simgr.explore(find=find_path, avoid=avoid_path)


if simgr.found:
    solution_state = simgr.found[0]
    buffer0 = solution_state.globals['buffer0']
    buffer1 = solution_state.globals['buffer1']
    password0 = solution_state.solver.eval(buffer0, cast_to=bytes)
    password1 = solution_state.solver.eval(buffer1, cast_to=bytes)
    print('password0: {}'.format(int.from_bytes(password0, 'little')))
    print('password1: {}'.format(int.from_bytes(password1, 'little')))
else:
    raise Exception('Could not find the solution')
