#!/bin/bash

# Generate the readelf output for shadow stack
readelf --wide -s attack-return.out > ./attack-return-readelf

# Generate the parsed log file from the direct PT output
../tools/pt/pt ./attack-return-syscall.log > ./attack-return-syscall.parsed.log
../tools/pt/pt ./attack-return-shadow-stack.log > ./attack-return-shadow-stack.parsed.log
../tools/pt/pt ./attack-return-proc-end.log > ./attack-return-proc-end.parsed.log

# Generate annotated griffin traces for shadow stack
python ./griffin-trace-annotator/annotate_griffin_trace.py ./attack-return-syscall.parsed.log ./attack-return-readelf > attack-return-syscall.annotated.log
python ./griffin-trace-annotator/annotate_griffin_trace.py ./attack-return-shadow-stack.parsed.log ./attack-return-readelf > attack-return-shadow-stack.annotated.log
python ./griffin-trace-annotator/annotate_griffin_trace.py ./attack-return-proc-end.parsed.log ./attack-return-readelf > attack-return-proc-end.annotated.log
