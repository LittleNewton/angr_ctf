import angr
import claripy
import sys

# 这里的 input 完全是用来对比的，所以不需要手动给它设置为某种需要 claripy 求解的变量。

passwd_bss_addr = 0x0804e02c


class ReplaceCmp(angr.SimProcedure):
    def run(self, buffer_addr, size):
        buffer = self.state.memory.load(buffer_addr, size)
        COMPARED_STR = b"XFQUUEQFKBECVEJF"
        return claripy.If(buffer == COMPARED_STR, claripy.BVV(1, 32), claripy.BVV(0, 32))


def find_path(state):
    return b'Good Job.' in state.posix.dumps(sys.stdout.fileno())


def avoid_path(state):
    return b'Try again.' in state.posix.dumps(sys.stdout.fileno())


bin_path = './10_angr_simprocedures.elf'
proj = angr.Project(bin_path)

init_state = proj.factory.entry_state()


# hook the function of char cmp
proj.hook_symbol('check_equals_XFQUUEQFKBECVEJF', ReplaceCmp())

simgr = proj.factory.simgr(init_state)
simgr.explore(find=find_path, avoid=avoid_path)

if simgr.found:
    solution_state = simgr.found[0]
    print(solution_state.posix.dumps(sys.stdin.fileno()))
else:
    raise Exception('Could not find the solution')
