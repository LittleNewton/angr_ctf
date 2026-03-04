"""
先把上下文跑出来，再绕开某个会 fork 的逻辑点，用你手工/逆向得到的约束把它“等价替换”掉，然后直接求模型。

https://chatgpt.com/c/699fa481-1444-8387-ba64-191ca6ea0009

"""


import angr
import claripy
import sys

# bss
buff_addr = 0x0804c028
buff_size = 0x10
passwd_addr = 0x0804c03c

bin_path = './08_angr_constraints.elf'
project = angr.Project(bin_path)

start_addr = 0x080492dd  # aftre scanf
init_state = project.factory.blank_state(addr=start_addr)

buffer = claripy.BVS('buffer', buff_size * 8)
init_state.memory.store(buff_addr, buffer)

check_addr = 0x08049329  # last insn before calling check_equals()
simgr = project.factory.simgr(init_state)
simgr.explore(find=check_addr)
check_state = simgr.found[0]

passwd = check_state.memory.load(buff_addr, buff_size)
compared_str = "XFQUUEQFKBECVEJF"

# 通过 decompiler, 提前知道如何比较才能避免路径爆炸
# buffer 里的内容反正是原地修改，所以直接 load 出来，然后和 compared_str 比较就好了
check_state.add_constraints(passwd == compared_str)
print("password: {}".format(check_state.solver.eval(buffer, cast_to=bytes)))
