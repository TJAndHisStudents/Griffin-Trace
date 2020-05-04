# Griffin Policy Generation
Scripts and environment to generate policies for Griffin

## Generating Policies
To generate policies, compile the intended program using clang/LLVM with the debug flag (-g) (and a few more details - see the Dockerfile for full settings). You'll need to generate bitcode and the resultant binary. This step is detailed in full in the Dockerfile for coreutils.

Once you have the bitcode, run the FPT analysis (in another git repo):

```
opt -load /root/llvm-build/lib/libfpt.so -f -fpt < [BITCODE FILE] > [TRANSFORMED FILE] 2> [FPT FILE]
```

To generate a policy, run the python script (generate_policy.py) with the first argument provided as the binary, and the second argument provided as the bitcode.
