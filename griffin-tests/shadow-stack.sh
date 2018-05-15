#!/bin/bash

# Forward Edge Tests

# Compile the program we need
gcc attack-return.c -o attack-return.out

# Clear the dmesg output without reading
dmesg -C

# Run the test without any settings
echo -n attack-return.out > /sys/kernel/debug/pt_monitor
./attack-return.out
echo -e "\x00" | tee /sys/kernel/debug/pt_monitor

# Sleep - Griffin runs on separate threads and lags behind the program
# EXCEPT for when system calls are made and require immediate attention
# In which case Griffin will catch up to the system call
sleep 3

# Run the test with system call capture
echo -n attack-return.out > /sys/kernel/debug/pt_monitor
echo -n 2 > /sys/kernel/debug/pt_trace_syscall
./attack-return.out
cp /var/log/pt.log ./attack-return-syscall.log
cp /var/log/pt.violation.log ./attack-return-syscall.violation.log
echo -e "\x00" | tee /sys/kernel/debug/pt_monitor

# Catch up and wait
sleep 3

# Run the test with shadow stack capture
echo -n attack-return.out > /sys/kernel/debug/pt_monitor
echo -n 3 > /sys/kernel/debug/pt_trace_shadow_stack
./attack-return.out
cp /var/log/pt.log ./attack-return-shadow-stack.log
cp /var/log/pt.violation.log ./attack-return-shadow-stack.violation.log
echo -e "\x00" | tee /sys/kernel/debug/pt_monitor

# Catch up and wait
sleep 3

# Run the test with forward edge capture
echo -n attack-return.out > /sys/kernel/debug/pt_monitor
echo -n 3 > /sys/kernel/debug/pt_trace_fwd_edge
./attack-return.out
echo -e "\x00" | tee /sys/kernel/debug/pt_monitor

# Catch up and wait
sleep 3

# Run the test with process end capture
echo -n attack-return.out > /sys/kernel/debug/pt_monitor
echo -n 6 > /sys/kernel/debug/pt_trace_proc_end
./attack-return.out
cp /var/log/pt.log ./attack-return-proc-end.log
cp /var/log/pt.violation.log ./attack-return-proc-end.violation.log
echo -e "\x00" | tee /sys/kernel/debug/pt_monitor

# Catch up and wait
sleep 3

# Run the test with process end capture
echo -n attack-return.out > /sys/kernel/debug/pt_monitor
echo -n -e "0000000000400c1800000000004004300000000000400400" | sudo tee -a /sys/kernel/debug/pt_trace_addresses
./attack-return.out
cp /var/log/pt.log ./attack-return-addresses.log
cp /var/log/pt.violation.log ./attack-return-addresses.violation.log
echo -e "\x00" | tee /sys/kernel/debug/pt_monitor

# Catch up and wait
sleep 3


# Print out the full dmesg result
dmesg