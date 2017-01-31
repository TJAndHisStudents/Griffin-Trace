GRIFFIN
=======

Griffin is a general operating system mechanism for Control-Flow
Integrity (CFI) enforcement.  At a high level, it collects the
program's runtime control-flow traces using Intel Processor Trace
(PT), and checks the trace against some CFI policy in the kernel
while the program runs.  Griffin blocks on security-sensitive
system calls and allows them to occur only when no CFI violation
is detected.  The CFI policy can be passed from the user space
at runtime (e.g., forward-edge policy) or enforced without being
specified explicitly (e.g., shadow stack for backward edges).

HOW TO USE
==========
1. Build and install the Griffin kernel on your system:  
   ```cp config .config```  
   ```make -j8```  
   ```make modules_install install```
2. Tell Griffin what to monitor:  
   ```$ echo -n a.out > /sys/kernel/debug/pt_monitor```
3. Enable online mode (optional, otherwise Griffin will save the
   trace to `/var/log/pt.log`):   
   ```$ echo -n 1 > /sys/kernel/debug/pt_mode```
4. Run the program with the default shadow-stack protection:   
   ```$ /path/to/a.out```
5. To check on forward edges, dump the policy to the file
   `/sys/kernel/debug/pt_policy` in the process context:   
   ```$ LD_PRELOAD=/path/to/policy_loader.so /path/to/a.out```

HOW IT WORKS
============

The implementation of Griffin is mostly contained in a single
file: `arch/x86/kernel/pt.c`.  When a process `execve` a program,
`pt_on_execve` will be invoked.  Griffin checks if the program is
of interest (`pt_should_monitor`), and does various setups (e.g.,
mapping mirror pages and the policy matrix) before turning on
Intel PT tracing (`pt_attach`).  `pt_attach` allocates trace buffers
and configures the related model specific registers for the current
task.

When a trace buffer fills, an interrupt will be triggered.  The
interrupt handler (`pt_on_interrupt`) assigns the filled trace buffer
to a worker thread (`pt_move_trace_to_work`) and allocates a new
trace buffer to resume execution (`pt_flush_trace`).  Worker threads
(`pt_work`) then recover the control flow (`pt_recover`) and pass the
output to the sequential phase (`pt_submit_buffer`, `pt_process_buffer`).

When the monitored process makes a system call, `pt_on_syscall` will
be invoked.  Griffin blocks security-sensitive system calls and checks
all pending trace buffers before continuing.

When the monitored process exits, `pt_on_exit` will be invoked.  It
disables tracing, flushes the remaining trace buffer and frees memory.

Mirror Pages
------------

Griffin relies on mirror pages for recovering the control flow and
enforcing CFI policies.  For each monitored process, Griffin maps
mirror pages at a fixed offset (`MIRROR_DISTANCE`) from its executable
pages in the user-level address space (`pt_mirror_page`).  In the
current implementation, Griffin maps ten mirror pages per code page.
The first eight mirror pages store the pointers to `pt_block` -- a
data structure encoding the disassembled information for each executed
basic block (`pt_disasm_block`).  `pt_get_block` stores the pointers
to these mirror pages.  The last two mirror pages store the indices of
indirect branches and targets to the policy matrix.  They are filled
by `pt_policy_write`, which is the write handler of the debug file
`/sys/kernel/debug/pt_policy`.  This interface allows the dynamic
loader to dump the CFI policy at runtime.

Offline Mode
------------

Griffin's offline mode allows save a trace of a monitored process to
disk.  Whether Griffin is running in the offline mode is determined
by `pt_offline_mode`.  For example, `pt_work` dumps the assigned trace
buffer to disk rather than processing it when `pt_offline_mode` is true.
