#!/bin/bash

# Compile the program we need
gcc -DINVALID attack-call.c -o attack-call.out

# Clear the dmesg output without reading
sudo dmesg -C

# Set binary for trace
echo -n attack-call.out | sudo tee /sys/kernel/debug/pt_monitor >/dev/null

# Enable online mode and run binary
echo -n 1 | sudo tee /sys/kernel/debug/pt_mode >/dev/null
sudo LD_PRELOAD=$BASE/griffin.so GRIFFIN_POLICY_PATH=$BASE/attack-call.txt-policy.bin ./attack-call.out

# Turn off tracing
echo -e "\x00" | sudo tee /sys/kernel/debug/pt_monitor >/dev/null

# Print out the full dmesg result
dmesg
