# Strip source code from BTF

Remove source code from a compiled BPF program while preserving BTF.

Clang [always](https://reviews.llvm.org/D52950) inserts source code
into `.BTF` section when compiling BPF with `-g`.
This is problematic if the developer does not want to disclose the source
but wants to provide BTF for easy interfacing with the program.

Dependencies: `pyelftools`.

Usage:

```sh
# Compile the code
clang -g -emit-llvm ... test.c -o test.ll
llc -march=bpf -filetype=obj test.ll -o test.o

# Strip standard debug info
llvm-objcopy --strip-debug test.o

# Strip source code
./strip-source-from-btf.py test.o
```
