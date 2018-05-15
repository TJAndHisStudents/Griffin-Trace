#!/bin/bash

# Forward Edge Tests

# Compile the program we need
gcc -DINVALID attack-call.c -o attack-call.out

# Clear the dmesg output without reading
dmesg -C

# Run the test without any settings
echo -n attack-call.out > /sys/kernel/debug/pt_monitor
LD_PRELOAD=`pwd`/griffin.so GRIFFIN_POLICY_PATH=`pwd`/attack-call.txt-policy.bin ./attack-call.out
echo -e "\x00" | tee /sys/kernel/debug/pt_monitor

# Sleep - Griffin runs on separate threads and lags behind the program
# EXCEPT for when system calls are made and require immediate attention
# In which case Griffin will catch up to the system call
sleep 3

# Run the test with system call capture
echo -n attack-call.out > /sys/kernel/debug/pt_monitor
echo -n 2 > /sys/kernel/debug/pt_trace_syscall
LD_PRELOAD=`pwd`/griffin.so GRIFFIN_POLICY_PATH=`pwd`/attack-call.txt-policy.bin ./attack-call.out
cp /var/log/pt.log ./attack-call-syscall.log
cp /var/log/pt.violation.log ./attack-call-syscall.violation.log
echo -e "\x00" | tee /sys/kernel/debug/pt_monitor

# Catch up and wait
sleep 3

# Run the test with shadow stack capture
echo -n attack-call.out > /sys/kernel/debug/pt_monitor
echo -n 3 > /sys/kernel/debug/pt_trace_shadow_stack
LD_PRELOAD=`pwd`/griffin.so GRIFFIN_POLICY_PATH=`pwd`/attack-call.txt-policy.bin ./attack-call.out
echo -e "\x00" | tee /sys/kernel/debug/pt_monitor

# Catch up and wait
sleep 3

# Run the test with forward edge capture
echo -n attack-call.out > /sys/kernel/debug/pt_monitor
echo -n 3 > /sys/kernel/debug/pt_trace_fwd_edge
LD_PRELOAD=`pwd`/griffin.so GRIFFIN_POLICY_PATH=`pwd`/attack-call.txt-policy.bin ./attack-call.out
cp /var/log/pt.log ./attack-call-fwd-edge.log
cp /var/log/pt.violation.log ./attack-call-fwd-edge.violation.log
echo -e "\x00" | tee /sys/kernel/debug/pt_monitor

# Catch up and wait
sleep 3

# Run the test with process end capture
echo -n attack-call.out > /sys/kernel/debug/pt_monitor
echo -n 6 > /sys/kernel/debug/pt_trace_proc_end
LD_PRELOAD=`pwd`/griffin.so GRIFFIN_POLICY_PATH=`pwd`/attack-call.txt-policy.bin ./attack-call.out
cp /var/log/pt.log ./attack-call-proc-end.log
cp /var/log/pt.violation.log ./attack-call-proc-end.violation.log
echo -e "\x00" | tee /sys/kernel/debug/pt_monitor

# Catch up and wait
sleep 3

# Print out the full dmesg result
dmesg