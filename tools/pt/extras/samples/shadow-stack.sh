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
