import angr


bin_path = './01_angr_avoid.elf'
proj = angr.project.Project(bin_path)
entry_state = proj.factory.entry_state()
simgr = proj.factory.simgr(entry_state)

obj_path_addr = 0x08049260    # puts('maybe good')
avoid_addr = 0x08049223  # function: avoid_me()
simgr.explore(find=obj_path_addr, avoid=avoid_addr)

if simgr.found:
    print("Found the target address!")
    found_state = simgr.found[0]
    print(found_state.posix.dumps(0))
else:
    print("Couldn't find the target address.")
