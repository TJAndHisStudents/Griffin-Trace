Introduction
============

FPT (Function Pointer Target) is an analysis tool that uses a taint-based approach to identify indirect calls and compute a list of possible targets for that call. It is built as an LLVM pass and thus requires an installation of LLVM in order to run.

This tool has been tested with LLVM versions 3.5 and 3.7, but requires a later version than 3.4. It may work with more recent versions of LLVM, but this has not been tested.

Compiling LLVM + Tool From Source
==========================

1. LLVM can be downloaded from the following link:

http://llvm.org/releases/download.html

2. Extract the contents to a directory of your choice for installation.

3. Run "mkdir lib/Transforms/FPT"

4. Place this tool in the newly created directory

5. Modify the CMakeLists.txt in the LLVM root directory. After line 579 add "add_subdirectory(lib/Transforms/FPT)

6. Build llvm using CMake following the guide here:

http://llvm.org/releases/3.7.0/docs/CMake.html

7. (Optional) Run "sudo make install" in order to install LLVM tools into your /bin/

8. Execute the tool similar to other LLVM passes:

$opt path/to/LLVMFPT.so -fpt path/to/bitcode/file


Building with an already installed version of LLVM
============

Suppose LLVM is installed at `/usr/lib/llvm`.

```
$ export LLVM_DIR=/usr/lib/llvm/share/llvm/cmake
$ mkdir fpt_build
$ cd fpt_build
$ cmake ../fpt
$ make
```

Compiling Autotooled Projects with LLVM
=======================================

An easy method for compiling programs with LLVM is by using the LLVM Gold Linker. In order to accomplish this start by installing a recent version of binutils.

You can find versions of binutils here:

http://ftp.gnu.org/gnu/binutils/

Follow the guide here to install the Gold Linker:

http://llvm.org/docs/GoldPlugin.html

Once installed, follow the guide here to compile auto tooled projects:

http://gbalats.github.io/2015/12/10/compiling-autotooled-projects-to-LLVM-bitcode.html






