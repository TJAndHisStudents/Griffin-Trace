#!/bin/bash

# Generate the readelf output for forward edge
readelf --wide -s attack-call.out > ./attack-call-readelf

# Generate the parsed log file from the direct PT output
../tools/pt/pt ./attack-call-syscall.log > ./attack-call-syscall.parsed.log
../tools/pt/pt ./attack-call-fwd-edge.log > ./attack-call-fwd-edge.parsed.log
../tools/pt/pt ./attack-call-proc-end.log > ./attack-call-proc-end.parsed.log

# Generate annotated griffin traces for forward edge
python ./griffin-trace-annotator/annotate_griffin_trace.py ./attack-call-syscall.parsed.log ./attack-call-readelf > attack-call-syscall.annotated.log
python ./griffin-trace-annotator/annotate_griffin_trace.py ./attack-call-fwd-edge.parsed.log ./attack-call-readelf > attack-call-fwd-edge.annotated.log
python ./griffin-trace-annotator/annotate_griffin_trace.py ./attack-call-proc-end.parsed.log ./attack-call-readelf > attack-call-proc-end.annotated.log
