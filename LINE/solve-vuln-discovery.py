import angr, claripy

# Load the binary into an angr project
proj = angr.Project("toy-program")
cfg = proj.analyses.CFG()

# Specify the entry point of the program
entry = proj.kb.functions['_start'].addr

# This time, the initialization is a bit different. The application takes a commandline argument, so we must:
# first, create a symbolic bitvector representing the argument.
# We're interested in the last few bytes (the part that will actually overflow the return address), so make it a
# concatination of 60 concrete bytes and 60 symbolic bytes.
arg = claripy.BVV("A"*60).concat(claripy.BVS("arg", 240))
# next, create a state with this argument
state = proj.factory.entry_state(args=['toytoytoy', arg])

# Create a simulation manager to control the execution
simgr = proj.factory.simgr(state)

# Start the execution
addr_of_win = proj.kb.functions['sub_100003ef0'].addr
simgr.explore(find=addr_of_win) # specify the address to be found

# Check if there are any found paths
if len(simgr.found) > 0:
    print("Possible buffer overflow found.")
    print("Found path:", simgr.found[0])
else:
    print("No buffer overflow found.")



