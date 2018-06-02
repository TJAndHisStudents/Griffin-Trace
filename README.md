GRIFFIN TRACE
=============

Griffin Trace is an application of the Griffin Control-Flow Integrity (CFI) monitor. Griffin Trace watches a program during runtime and records traces during specific triggers. Right now, Griffin Trace can report the traces at Forward Edge and Shadow Stack violations, at the conclusion of a program run (either naturally or by an exception), at system calls, and at specific addresses.

## WARNING

Griffin Trace uses a technique to reconstruct the control flow of a program in realtime in order to watch for forward-edge and  shadow stack violations, and to identify specific address triggers. These require the use of mirror pages, which currently allocate user-space memory as both readable and writable. **We do not recommend using this feature on deployment hardware at this time, and restrict usage only to development and testing environments.**

## Requirements

Griffin is a kernel patch that relies on specific Intel Processor Trace (PT) hardware. The Griffin kernel will only work on an Intel processor that includes Processor Trace. Modern Intel processors, such as [Intel Xeon](https://software.intel.com/en-us/articles/intel-xeon-processor-e5-2600-v4-product-family-technical-overview) include this hardware.

## Installation & Usage

To build and install the Griffin Trace kernel on your system, check out our Wiki pages for the latest documentation: [Griffin Trace Wiki](https://github.com/TJAndHisStudents/Griffin-Trace/wiki/0.-Home).

## Reviewing the Trace

To read over the trace, you can run the PT trace tool provided in our Griffin kernel patch. The tool is located in ```./tools/pt/``` subfolder within the Griffin kernel.

1) Compile the tool: ```$ make /path/to/griffin/tools/pt/```
2) Then provide the PT log generated by Griffin Trace: ```$ /path/to/griffin/tools/pt/pt /path/to/pt.log```

This will produce a fairly large trace depending on the program, so you may want to feed the output into another file.

### Trace Analysis Tools

#### Function & CFI Annotation

The Griffin Trace Annotator is included in the ```./griffin-tests/``` folder in this repository. The Annotator adds information to the PT log generated by Griffin Trace, and annotates any instructions used as entrypoints to functions, all system calls, and forward-edge and shadow stack CFI violations.

View the [Griffin Trace Annotator](https://github.com/TJAndHisStudents/griffin-trace-annotator/) for more information.
