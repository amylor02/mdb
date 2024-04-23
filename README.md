# mdb
 Debugger in C for ELF files. Final project for Binary Analysis class @ UCY.

After compiling, run with 
```
./mdb ./executable_to_debug
```

Implemented functionalities:

Setting, listing and deleting breakpoints
```
$ b main
$ b *0xdeadbeef
$ l
BREAKPOINT 0 AT ADDR 0x4005a6
BREAKPOINT 1 AT ADDR 0xdeadbeef
$ d 0
$ d 1
```

