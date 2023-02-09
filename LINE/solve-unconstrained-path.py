import angr, claripy

# Load the binary into an angr project
project = angr.Project("toy-program", auto_load_libs=False)
#cfg = project.analyses.CFG()

print("finding the buffer overflow...")
# Specify the entry point of the program
#entry = project.kb.functions['_start'].addr


for input_size in range(1, 100):
    print(input_size)
    input_bv = claripy.BVS("input", input_size * 8)
    state = project.factory.entry_state(args=['toy-program', input_bv])
    sm = project.factory.simulation_manager(state, save_unconstrained=True)
    sm.run()
    if len(sm.deadended) > 0:
        print(f"Found a crash with input size {input_size}")
        break

while len(sm.unconstrained)==0:
    sm.step()
    
unconstrained_state = sm.unconstrained[0]
crashing_input = unconstrained_state.posix.dumps(0)
#cat crash_input.bin | ./CADET_00001.adapted will segfault
with open('crash_input.bin', 'wb') as fp:
    fp.write(crashing_input)
print("buffer overflow found!")
print(repr(crashing_input))



