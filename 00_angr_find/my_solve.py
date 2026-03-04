import angr
from IPython import embed

bin_path = './00_angr_find'
proj = angr.Project(bin_path)

print(hex(proj.entry))

entry_state = proj.factory.entry_state()

# Define the inital execution state.
simgr = proj.factory.simgr(entry_state)

obj_path_addr = 0x080492c5  # puts('good god')
simgr.explore(find=obj_path_addr)

if simgr.found:
    print("Found the target address!")
    found_state = simgr.found[0]
    print(found_state.posix.dumps(0))
else:
    print("Couldn't find the target address.")
