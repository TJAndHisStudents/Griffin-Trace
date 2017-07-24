GRIFFIN TRACE
=============

Griffin is a general operating system mechanism for Control-Flow
Integrity (CFI) enforcement. This repository distills the core of
Griffin's PT monitoring for use in generating full program traces.

## Requirements

Griffin is a kernel patch that relies on specific Intel Processor Trace (PT) hardware. The Griffin kernel will only work on an Intel processor that includes Processor Trace. Modern Intel processors, such as [Intel Xeon](https://software.intel.com/en-us/articles/intel-xeon-processor-e5-2600-v4-product-family-technical-overview) include this hardware.

## Installation

To build and install the Griffin kernel on your system, pull the Griffin kernel repository (this one), and in the top directory, run the following commands:

   ```$ cp config .config```  
   ```$ make -j8```  
   ```$ make modules_install install```

Note that you may need sudo access for the third command.

## How to Use
1. Tell Griffin what to monitor:  
	```$ echo -n a.out > /sys/kernel/debug/pt_monitor```
1. Run the program:
	```$ /path/to/a.out```
1. Retrieve the log output:
	```$ cp /var/log/pt.log ./pt.log```
1. Reset monitoring to stop Griffin:
	```$ echo -e "\x00" | tee /sys/kernel/debug/pt_monitor```

## Reviewing the Trace

To read over the trace, you can run the PT trace tool provided in our Griffin kernel patch. The tool is located in tools/pt/ within the Griffin kernel.

First, you'll need to compile the tool.

```$ make /path/to/griffin/tools/pt/```

Then you can use the tool to produce a legible trace:

```$ /path/to/griffin/tools/pt/pt /path/to/pt.log```

This will produce a fairly large trace depending on the program, so you may want to feed the output into another file.
