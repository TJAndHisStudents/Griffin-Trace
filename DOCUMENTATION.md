# Griffin: Documentation

Griffin is a general operating system mechanism for Control-Flow Integrity (CFI) enforcement. At a high level, it collects the program's runtime control-flow traces using Intel Processor Trace (PT), and checks the trace against some CFI policy in the kernel while the program runs. Griffin blocks on security-sensitive system calls and allows them to occur only when no CFI violation is detected. The CFI policy can be passed from the user space at runtime (e.g., forward-edge policy) or enforced without being specified explicitly (e.g., shadow stack for backward edges).

## Table of Contents

1. How It Works
	1. Mirror Pages
1. Requirements
1. Installation
1. Usage
	1. Shadow Stack
	1. Forward Edge
1. Logging
	1. Generating a Trace
	1. Reviewing the Trace


## How It Works

The implementation of Griffin is mostly contained in a single file: `arch/x86/kernel/pt.c`.  When a process `execve` a program, `pt_on_execve` will be invoked.  Griffin checks if the program is of interest (`pt_should_monitor`), and does various setups (e.g., mapping mirror pages and the policy matrix) before turning on Intel PT tracing (`pt_attach`).  `pt_attach` allocates trace buffers and configures the related model specific registers for the current task.

When a trace buffer fills, an interrupt will be triggered.  The interrupt handler (`pt_on_interrupt`) assigns the filled trace buffer to a worker thread (`pt_move_trace_to_work`) and allocates a new trace buffer to resume execution (`pt_flush_trace`).  Worker threads (`pt_work`) then recover the control flow (`pt_recover`) and pass the output to the sequential phase (`pt_submit_buffer`, `pt_process_buffer`).

When the monitored process makes a system call, `pt_on_syscall` will be invoked.  Griffin blocks security-sensitive system calls and checks all pending trace buffers before continuing.

When the monitored process exits, `pt_on_exit` will be invoked.  It disables tracing, flushes the remaining trace buffer and frees memory.


### Mirror Pages

Griffin relies on mirror pages for recovering the control flow and enforcing CFI policies.  For each monitored process, Griffin maps mirror pages at a fixed offset (`MIRROR_DISTANCE`) from its executable pages in the user-level address space (`pt_mirror_page`). In the current implementation, Griffin maps ten mirror pages per code page. The first eight mirror pages store the pointers to `pt_block` -- a data structure encoding the disassembled information for each executed basic block (`pt_disasm_block`).  `pt_get_block` stores the pointers to these mirror pages.  The last two mirror pages store the indices of indirect branches and targets to the policy matrix.  They are filled by `pt_policy_write`, which is the write handler of the debug file `/sys/kernel/debug/pt_policy`.  This interface allows the dynamic loader to dump the CFI policy at runtime.


## Requirements

Griffin is a kernel patch that relies on specific Intel Processor Trace (PT) hardware. The Griffin kernel will only work on an Intel processor that includes Processor Trace. Modern Intel processors, such as [Intel Xeon](https://software.intel.com/en-us/articles/intel-xeon-processor-e5-2600-v4-product-family-technical-overview) include this hardware.

For generating policies for Griffin to monitor and enforce forward edges, you'll need LLVM 3.7 (as of now - we are working on supporting 3.7 through 4.0) with the ```opt``` package available. You'll pull the FPT tool from [our FPT repository](https://github.com/TJAndHisStudents/FPT) and install the package directly as an optimization within LLVM.


## Installation

To build and install the Griffin kernel on your system, pull the Griffin kernel repository (this one), and in the top directory, run the following commands:

   ```$ cp config .config```  
   ```$ make -j8```  
   ```$ make modules_install install```

Note that you may need sudo access for the third command.


## Usage


### Shadow Stack

It is possible to start monitoring programs for shadow stack enforcement once the kernel and Griffin patch is installed. To do this, you'll tell Griffin what program to watch, enable online mode for real-time monitoring, and then run the program. The results can be viewed via ```dmesg``` during or after the program runs. For example:

1. Tell Griffin what to monitor:  

	```$ echo -n a.out > /sys/kernel/debug/pt_monitor```

1. Enable online mode (optional, otherwise Griffin will save the trace to `/var/log/pt.log`):   

	```$ echo -n 1 > /sys/kernel/debug/pt_mode```

1. Run the program with the default shadow-stack protection:   

	```$ /path/to/a.out```

1. Reset Griffin monitoring

	```$ echo -e "\x00" | tee /sys/kernel/debug/pt_monitor```

1. Review the results:

	```$ dmesg```


### Forward Edge

Monitoring and enforcing forward edges require generating an enforcement policy that Griffin can use during program runtime to enforce legal forward edges. To generate the policies needed, you'll need to pull the Function Pointer Trace tool from [our FPT repository](https://github.com/TJAndHisStudents/FPT) and install it to LLVM. The directions for installing FPT are provided in the other repository.

You will also need to pull the Python script used to generate the policy from the FPT file and the executable. This can be found as the file ```generate_policy.py``` within [the Griffin Policy Generation repository](https://github.com/TJAndHisStudents/griffin-policy-generation).

Once you have installed the FPT tool, you will need to do the following:

1. Compile your test program, generating bitcode to insert into the tool to generate the FPT file
1. Fully compile your test program, generating the executable
1. Run the policy generation script:

	```$ python generate_policy.py binary fpt_file```

With the generated policy file, you can run the program to enforce forward edges as follows:

1. Tell Griffin what to monitor:  

	```$ echo -n a.out > /sys/kernel/debug/pt_monitor```

1. Enable online mode (optional, otherwise Griffin will save the trace to `/var/log/pt.log`):   

	```$ echo -n 1 > /sys/kernel/debug/pt_mode```

1. To run the program and check on forward edges, dump the policy to the file `/sys/kernel/debug/pt_policy` in the process context:

	```$ LD_PRELOAD=/path/to/griffin.so GRIFFIN_POLICY_PATH=<policy-file> /path/to/a.out```

1. Reset Griffin monitoring

	```$ echo -e "\x00" | tee /sys/kernel/debug/pt_monitor```

1. Review the results:

	```$ dmesg```


## Logging

Griffin's offline mode allows save a trace of a monitored process to disk.  Whether Griffin is running in the offline mode is determined by `pt_offline_mode`.  For example, `pt_work` dumps the assigned trace buffer to disk rather than processing it when `pt_offline_mode` is true.


### Generating a Trace

To generate a trace while monitoring shadow stack, do the following:

1. Tell Griffin what to monitor:  

	```$ echo -n a.out > /sys/kernel/debug/pt_monitor```

1. Run the program with the default shadow-stack protection:   

	```$ /path/to/a.out```

1. Copy the PT log to your current directory (or wherever - but it must be done before resetting Griffin)

	```$ cp /var/log/pt.log ./pt.log```

1. Reset Griffin monitoring

	```$ echo -e "\x00" | tee /sys/kernel/debug/pt_monitor```


### Reviewing the Trace

To read over the trace, you can run the PT trace tool provided in our Griffin kernel patch. The tool is located in tools/pt/ within the Griffin kernel.

First, you'll need to compile the tool.

	```$ make /path/to/griffin/tools/pt/```

Then you can use the tool to produce a legible trace:

	```$ /path/to/griffin/tools/pt/pt /path/to/pt.log```

This will produce a fairly large trace depending on the program, so you may want to feed the output into another file.
