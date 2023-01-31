import angr
import claripy

# load the binary
project = angr.Project("overflow3-simplified_1", load_options={ 'auto_load_libs': False })

# This time, we will need access to symbols (to figure out where the "shell" function is, for example).
# Let's generate a CFG to fill in the knowledgebase.
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
    print("Checking saved EIP: " + saved_eip)

    # first, check if the return address points to a hook. If this is intact, then we assume there is no overflow
    if project.is_hooked(state.se.any_int(saved_eip)):
        return False

    # next, create constraints representing an unsafe condition. In this case,
    # let's check if the return address can point *outside* of the program.
    unsafe_constraints = [ state.se.Or(saved_eip < project.loader.min_addr, saved_eip > project.loader.max_addr) ]

    # check if the state is satisfiable with these conditions, and return True if it is
    return state.se.satisfiable(extra_constraints=unsafe_constraints)

# This time, the initialization is a bit different. The application takes a commandline argument, so we must:
# first, create a symbolic bitvector representing the argument.
# We're interested in the last few bytes (the part that will actually overflow the return address), so make it a
# concatination of 60 concrete bytes and 60 symbolic bytes.
pass
# next, create a state with this argument
pass
# now, create the simulation manager with that state as the initial state
simgr = project.factory.simgr(state)

# initiate a "vuln" stash
simgr.stashes['vuln'] = [ ]

# Since we have the address of main in the knowledgebase, let's make a less janky initialization procedure.
print("Initializing initial state...")
while simgr.active[0].addr != project.kb.functions['main'].addr:
    simgr.step()

# Now that we are all set up, let's loop until a vulnerable state has been found
print("Searching for the vulnerability!")
while not simgr.vuln:
    # step the simgr
    simgr.step()
    # after each step, move all states matching our vuln filter from the active stash to the vuln stash
    simgr.move('active', 'vuln', filter_func=state_vuln_filter)

# Now the fun part starts! Let's add a constraint that sets the overflowed return address to the "shell" function.
# First, grab the stored return address in the vuln state
print("Constraining saved return address!")
vuln_state = simgr.vuln[0]
pass
print("Overwritten EIP: " + overwritten_eip)
# Now, let's add a constraint to redirect that return address to the shell function
addr_of_shell = project.kb.functions['shell'].addr
pass

# and now let's explore the vuln stash until we reach the shell
print("Exploring to 'shell' function.")
pass

# now synthesize our pwning input!
pass
open("pwning_input", "w").write(pwning_input.split('\0')[0]) # since it's a string arg, we only care up to the first null byte
print("You can crash the program by doing:")
print('# ./overflow3-simplifie__1 "$(cat pwning_input)"')
