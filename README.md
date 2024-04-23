# mdb
 Debugger in C for ELF files. Final project for Binary Analysis class @ UCY.

After compiling, run with 
```
./mdb ./executable_to_debug
```

Example execution of debugging [test.c](/test.c) 
```
$ ./mdb ./test
pid: 4207
(mdb) b main
(mdb) r
 0x401164:	endbr64		

   0x401168:	pushq		%rbp
   0x401169:	movq		%rsp, %rbp
   0x40116c:	subq		$0x20, %rsp
   0x401170:	movl		%edi, -0x14(%rbp)
   0x401173:	movq		%rsi, -0x20(%rbp)
   0x401177:	movl		$0, -4(%rbp)
   0x40117e:	jmp		0x401189
   0x401180:	callq		0x401136
   0x401185:	addl		$1, -4(%rbp)
   0x401189:	cmpl		$4, -4(%rbp)
(mdb) l
BREAKPOINT 0      ADR: 0x401164              main
(mdb) si
 0x401168:	pushq		%rbp

   0x401169:	movq		%rsp, %rbp
   0x40116c:	subq		$0x20, %rsp
   0x401170:	movl		%edi, -0x14(%rbp)
   0x401173:	movq		%rsi, -0x20(%rbp)
   0x401177:	movl		$0, -4(%rbp)
   0x40117e:	jmp		0x401189
   0x401180:	callq		0x401136
   0x401185:	addl		$1, -4(%rbp)
   0x401189:	cmpl		$4, -4(%rbp)
   0x40118d:	jle		0x401180
(mdb) c
(mdb) l
BREAKPOINT 0      ADR: 0x401164              main
(mdb) d 0
(mdb) l
(mdb) c
Hello World.
Hello World.
Hello World.
Hello World.
Hello World.
Program finished
```

Implemented functionalities:

Setting, listing and deleting breakpoints.
```
$ b main
$ b *0xdeadbeef
$ l
BREAKPOINT 0 AT ADDR 0x4005a6  main
BREAKPOINT 1 AT ADDR 0xdeadbeef
$ d 0
$ d 1
```

Continuing execution, stepping into
```
$ c
$ si
```

