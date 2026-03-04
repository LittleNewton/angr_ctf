import angr
import claripy
import sys


def find_path(state):
    return b'Good Job.' in state.posix.dumps(sys.stdout.fileno())


def avoid_path(state):
    return b'Try again.' in state.posix.dumps(sys.stdout.fileno())


def solver():
    bin_path = './13_angr_static_binary.elf'
    proj = angr.Project(bin_path)
    init_state = proj.factory.entry_state()

    # 学习了一个 hook 库函数？如果是我自己执行，是不是也得这么弄？

    # hook the functions
    proj.hook(0x0804cd40, angr.SIM_PROCEDURES['libc']['scanf']())
    proj.hook(0x0804cd70, angr.SIM_PROCEDURES['libc']['printf']())
    proj.hook(0x08059620, angr.SIM_PROCEDURES['libc']['puts']())
    proj.hook(0x08066430, angr.SIM_PROCEDURES['libc']['strcmp']())
    proj.hook_symbol('__libc_start_main',
                     angr.SIM_PROCEDURES['glibc']['__libc_start_main']())

    simgr = proj.factory.simgr(init_state)
    simgr.explore(find=find_path, avoid=avoid_path)

    if simgr.found:
        solution_state = simgr.found[0]
        print(solution_state.posix.dumps(sys.stdin.fileno()).decode())
    else:
        raise Exception('Could not find the solution')


if __name__ == '__main__':
    solver()
