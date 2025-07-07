# Exploit Tech: Use After Free

**실습 환경 도커 파일**

```docker
FROM ubuntu:18.04

ENV PATH="${PATH}:/usr/local/lib/python3.6/dist-packages/bin"
ENV LC_CTYPE=C.UTF-8

RUN apt update
RUN apt install -y \
    gcc \
    git \
    python3 \
    python3-pip \
    ruby \
    sudo \
    tmux \
    vim \
    wget

# install pwndbg
WORKDIR /root
RUN git clone https://github.com/pwndbg/pwndbg
WORKDIR /root/pwndbg
RUN git checkout 2023.03.19
RUN ./setup.sh

# install pwntools
RUN pip3 install --upgrade pip
RUN pip3 install pwntools

# install one_gadget command
RUN gem install one_gadget -v 1.6.2

WORKDIR /root
```
<br>

**이미지 빌드/컨테이너 실행/쉘 실행**

```bash
IMAGE_NAME=ubuntu1804 CONTAINER_NAME=my_container; \
docker build . -t $IMAGE_NAME; \
docker run -d -t --privileged --name=$CONTAINER_NAME $IMAGE_NAME; \
docker exec -it -u root $CONTAINER_NAME bash
```

실습파일에 있는 도커 파일에 pwndbg 설치를 추가할려했는데 아무리 해도 안돼서 그냥 원래대로 빌드하고 실습 파일은 압축 해제한 뒤 수동으로 넣어줬다. (flag만 440 권한)  

<br>

**uaf_overwrite.c 파일**

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct Human {
  char name[16];
  int weight;
  long age;
};

struct Robot {
  char name[16];
  int weight;
  void (*fptr)();
};

struct Human *human;
struct Robot *robot;
char *custom[10];
int c_idx;

void print_name() { printf("Name: %s\n", robot->name); }

void menu() {
  printf("1. Human\n");
  printf("2. Robot\n");
  printf("3. Custom\n");
  printf("> ");
}

void human_func() {
  int sel;
  human = (struct Human *)malloc(sizeof(struct Human));

  strcpy(human->name, "Human");
  printf("Human Weight: ");
  scanf("%d", &human->weight);

  printf("Human Age: ");
  scanf("%ld", &human->age);

  free(human);
}

void robot_func() {
  int sel;
  robot = (struct Robot *)malloc(sizeof(struct Robot));

  strcpy(robot->name, "Robot");
  printf("Robot Weight: ");
  scanf("%d", &robot->weight);

  if (robot->fptr)
    robot->fptr();
  else
    robot->fptr = print_name;

  robot->fptr(robot);

  free(robot);
}

int custom_func() {
  unsigned int size;
  unsigned int idx;
  if (c_idx > 9) {
    printf("Custom FULL!!\n");
    return 0;
  }

  printf("Size: ");
  scanf("%d", &size);

  if (size >= 0x100) {
    custom[c_idx] = malloc(size);
    printf("Data: ");
    read(0, custom[c_idx], size - 1);

    printf("Data: %s\n", custom[c_idx]);

    printf("Free idx: ");
    scanf("%d", &idx);

    if (idx < 10 && custom[idx]) {
      free(custom[idx]);
      custom[idx] = NULL;
    }
  }

  c_idx++;
}

int main() {
  int idx;
  char *ptr;

  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);

  while (1) {
    menu();
    scanf("%d", &idx);
    switch (idx) {
      case 1:
        human_func();
        break;
      case 2:
        robot_func();
        break;
      case 3:
        custom_func();
        break;
    }
  }
}
```

<br>

**코드 분석**    
코드를 쭉 지켜보면 같은 크기의 `Human`과 `Robot` 구조체가 보인다.   

`human_func()`에서 `scanf()`를 사용할 때 인덱스 검사를 안하고 있다. 그리고 `free`로 `human` 포인터는 해제가 되었지만 내부 값은 여전히 존재하므로 취약점이 존재할 것이다.   

`robot_func()`의 `robot->fptr = print_name;` 을 보면 함수 주소를 저장하는 코드도 보인다.  



<br>

<img src="https://github.com/user-attachments/assets/c513d13d-9599-4510-9a78-09def2b35650" width=400>  

실제로 해보면서 답을 어떻게 구할지 확인해보자.  

<br>

**동적 분석**

```nasm
   0x0000000000000c71 <+0>:     push   rbp
   0x0000000000000c72 <+1>:     mov    rbp,rsp
   0x0000000000000c75 <+4>:     sub    rsp,0x10
   0x0000000000000c79 <+8>:     mov    rax,QWORD PTR fs:0x28
   0x0000000000000c82 <+17>:    mov    QWORD PTR [rbp-0x8],rax
   0x0000000000000c86 <+21>:    xor    eax,eax
   0x0000000000000c88 <+23>:    mov    rax,QWORD PTR [rip+0x2013a1]        # 0x202030 <stdin@@GLIBC_2.2.5>
   0x0000000000000c8f <+30>:    mov    ecx,0x0
   0x0000000000000c94 <+35>:    mov    edx,0x2
   0x0000000000000c99 <+40>:    mov    esi,0x0
   0x0000000000000c9e <+45>:    mov    rdi,rax
   0x0000000000000ca1 <+48>:    call   0x7c0 <setvbuf@plt>
   0x0000000000000ca6 <+53>:    mov    rax,QWORD PTR [rip+0x201373]        # 0x202020 <stdout@@GLIBC_2.2.5>
   0x0000000000000cad <+60>:    mov    ecx,0x0
   0x0000000000000cb2 <+65>:    mov    edx,0x2
   0x0000000000000cb7 <+70>:    mov    esi,0x0
   0x0000000000000cbc <+75>:    mov    rdi,rax
   0x0000000000000cbf <+78>:    call   0x7c0 <setvbuf@plt>
   0x0000000000000cc4 <+83>:    mov    eax,0x0
   0x0000000000000cc9 <+88>:    call   0x91c <menu>
   0x0000000000000cce <+93>:    lea    rax,[rbp-0xc]
   0x0000000000000cd2 <+97>:    mov    rsi,rax
   0x0000000000000cd5 <+100>:   lea    rdi,[rip+0x100]        # 0xddc
   0x0000000000000cdc <+107>:   mov    eax,0x0
   0x0000000000000ce1 <+112>:   call   0x7d0 <__isoc99_scanf@plt>
   0x0000000000000ce6 <+117>:   mov    eax,DWORD PTR [rbp-0xc]
   0x0000000000000ce9 <+120>:   cmp    eax,0x2
   0x0000000000000cec <+123>:   je     0xd04 <main+147>
   0x0000000000000cee <+125>:   cmp    eax,0x3
   0x0000000000000cf1 <+128>:   je     0xd10 <main+159>
   0x0000000000000cf3 <+130>:   cmp    eax,0x1
   0x0000000000000cf6 <+133>:   jne    0xd1b <main+170>
   0x0000000000000cf8 <+135>:   mov    eax,0x0
   0x0000000000000cfd <+140>:   call   0x958 <human_func>
   0x0000000000000d02 <+145>:   jmp    0xd1b <main+170>
   0x0000000000000d04 <+147>:   mov    eax,0x0
   0x0000000000000d09 <+152>:   call   0x9f2 <robot_func>
   0x0000000000000d0e <+157>:   jmp    0xd1b <main+170>
   0x0000000000000d10 <+159>:   mov    eax,0x0
   0x0000000000000d15 <+164>:   call   0xaae <custom_func>
   0x0000000000000d1a <+169>:   nop
   0x0000000000000d1b <+170>:   jmp    0xcc4 <main+83>
```

우선 main 함수를 디스어셈 해주고 브레이크 포인트를 어디 걸지 봐준다.
case를 나누기 전에 main+112 scanf 에서 걸어준다. 

`human_func()`에서 어떻게 되는지 알아야 하기 때문에 case 1번으로 들어간다.

`human_func()`을 만나면 `si` 로 진입해주자.

![image (1)](https://github.com/user-attachments/assets/22b9523a-30cf-4ba3-a8e4-dc432d7e8b53)  

`malloc` 에 들어가기 전, `0x20` 크기를 인자로 설정하고 `heap`에 동적 할당이 된 것도 알아 볼 수 있다.   

`name` 설정이 끝난 후까지 옮긴 후 상황을 살펴보면,  

<br>

<img src="https://github.com/user-attachments/assets/ee3ba966-b33d-4271-97dd-554a9b16b00f" width=700>  

이렇게  Human 이라는 문자열이 구조체 속에 들어간 것이 보인다.   

<br>

![image (3)](https://github.com/user-attachments/assets/6183df22-9b3a-47be-bea9-7ebfde0e4b10)  

그리고 나머지 `Weight`과 `Age` 에 임의로 100 이라는 정수 값을 넣어줬더니  
각각 0x64 씩 가져간 모습을 볼 수 있다.  

<br>

![image](https://github.com/user-attachments/assets/889f0557-8410-4a53-9c82-a1956466fdf9)


그리고 이 값들은 `free` 이후에도 여전히 값을 가지고 있다.  

`heap` 명령어를 통해 `free` 상태가 된 청크를 잘 봐두자.  

```nasm
Free chunk (tcachebins) | PREV_INUSE
Addr: 0x555555603250
Size: 0x31
```
<br>

다음으로 main으로 나간 뒤 case 2를 선택하여 `robot_func`에 진입해준다.  

<br>

![image](https://github.com/user-attachments/assets/59d32dee-b056-400c-a8cd-a17e017266a8)


그러면 이전과 같은 청크를 재사용하고 있는 것이 보인다.

```nasm
Allocated chunk | PREV_INUSE
Addr: 0x555555603250
Size: 0x31
```
<BR>

그리고 c 코드를 살펴보면,  

```c
  if (robot->fptr)
    robot->fptr();
  else
    robot->fptr = print_name;
```
<br>

여기서 `robot->fptr = print_name;` 로 함수의 주소를 저장하게 하는 곳이 보인다.   
따라서 해당 조건을 만족시키도록, gdb 를 다시 시작해서 else 문을 통과하도록, 바로 case2로 들어가줬다.  
그리고 임의로 100이란 숫자를 넣고 free 이전에서 heap 상황을 보면,  

<br>

![image](https://github.com/user-attachments/assets/6271aeee-b848-45f7-a7f6-1ffea84245e8)

아래처럼 쌓이게 된다.

| Robot |
| --- |
| 100(임의 수) |
| 함수 주소 |

<br>
일단 /bin/sh 부터 찾아보고,

<br>

![image](https://github.com/user-attachments/assets/5a491c1a-3672-4535-9072-b028b697f85d)

<br>

![image](https://github.com/user-attachments/assets/e4fa5db8-72b6-49c6-849d-93a8e2f4aef5)


<br>

리턴가젯을 찾아봤는데 쓸만한게 있다.   
저걸 사용해서 아래처럼 paylaod를 짜면 되겠다.  

```c
payload 에 추가할 것들 
----------------------
+ pop rdi ; ret 가젯 주소
+ "/bin/sh" 문자열 주소
+ system 함수 주소
```
<br>
지금 상황에서 리턴 가젯과 binsh는 절대주소니까 system 함수만 찾아주면 된다.  

그럼 이제 system 함수 주소를 찾기 위해서 libc의 베이스 주소를 알아내보자  

<br>

libc 주소를 얻어야하는데, ptmalloc2의 unsorted bin 취약점을 이용해보자.    
unsorted bin 연결 시 fd/bk 필드에 libc 주소가 들어가게 된다.    
큰 청크를 해제하면 unsorted bin에 들어가는데, 이때 fd와 bk 필드에 libc 내부의 주소들이 저장된다.   
이 주소를 읽어내면 libc base 주소를 계산할 수 있다.   

![image](https://github.com/user-attachments/assets/981c6ae8-2b5e-46ae-8383-509fe7119c73)

이렇게 1280으로 할당한 각 공간들의 상태를 확인해보면,   

<br>

![image](https://github.com/user-attachments/assets/f0f82be8-f567-4dac-a747-d93a023084d6)

그리고 해당 `fd`와 `bk` 주소인 `0x7ffff7dcdca0`을 살펴보면,    

`/lib/x86_64-linux-gnu/libc-2.27.so`로 `libc` 파일에 들어있는 것을 알 수 있다.  

<br>

![image](https://github.com/user-attachments/assets/758ba2e1-2b96-46c4-9ce2-9dd5e06cea51)


이곳에서 `libc`가 매핑된 주소를 찾아준 뒤 빼주면 베이스 주소를 알아낼 수 있다.    

- `0x7ffff79e2000     0x7ffff7bc9000 r-xp   1e7000      0 /lib/x86_64-linux-gnu/libc-2.27.so`
- 주소: `0x7ffff79e2000`  

```bash
pwndbg> p/x 0x7ffff7dcdca0 - 0x7ffff79e2000
$1 = 0x3ebca0
```

이런 식으로 베이스 주소의 오프셋을 구했다.  


<br>



![image](https://github.com/user-attachments/assets/054ecbec-7ac7-4a49-ab6a-fdeb583e96b8)

그리고  해제한 청크에 다시 Z 단일 문자열을 넣었더니   
0x7ffff7dcdca0 → 0x7ffff7dc0a5a 로 변했다.   


libc base랑 offset은 구햇는데 가젯쓰는게아닌듯
