import angr

proj = angr.Project("toy-program")

def check_overflow(state):
    buf_size = state.mem[state.regs.rdi].size
    src_size = state.mem[state.regs.rsi].size
    if src_size >= buf_size:
        raise Exception("Buffer overflow detected")

strcpy_addr = 0x100003f88 #proj.loader.find_symbol("strcpy").rebased_addr

# Create a SimProcedure object for the hook
class OverflowCheck(angr.SimProcedure):
    def run(self, *args, **kwargs):
        check_overflow(self.state)

proj.hook(strcpy_addr, OverflowCheck(length=64))

state = proj.factory.entry_state()
sim = proj.factory.simulation_manager(state)
sim.run()