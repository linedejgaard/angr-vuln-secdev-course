import angr, claripy

# Load the binary into an angr project
project = angr.Project("toy-program", auto_load_libs=False)
cfg = project.analyses.CFG()

print("finding the buffer overflow...")
# Specify the entry point of the program
entry = project.kb.functions['_start'].addr

# This time, the initialization is a bit different. The application takes a commandline argument, so we must:
# first, create a symbolic bitvector representing the argument.
# We're interested in the last few bytes (the part that will actually overflow the return address), so make it a
# concatination of 60 concrete bytes and 60 symbolic bytes.
arg = claripy.BVV("A"*60).concat(claripy.BVS("arg", 240))
# next, create a state with this argument
state = project.factory.entry_state(args=['toytoytoy', arg])

sm = project.factory.simulation_manager(state, save_unconstrained=True)

#symbolically execute the binary until an unconstrained path is reached
while len(sm.unconstrained)==0:
    sm.step()
unconstrained_state = sm.unconstrained[0]
crashing_input = unconstrained_state.posix.dumps(0)
#cat crash_input.bin | ./CADET_00001.adapted will segfault
with open('crash_input.bin', 'wb') as fp:
    fp.write(crashing_input)
print("buffer overflow found!")
print(repr(crashing_input))



