# 실습 환경 구축  

실습 환경을 구축하고, payload를 보내기까지 정말 많은 방법들이 있지만,  
노트북으로 문제를 풀 땐 메모리가 부족한 경우가 많아서 내가 자주 쓰는 방법으로 소개해볼까 한다.   


<br>

### 실습 문제 다운  

```bash
wget "실습 문제 링크" -O 파일이름.zip
unzip 파일이름.zip
```

<br>

## Docker 파일  

분석용 환경과 실습용 환경이 별개로 존재한다.   

실습용 파일에 pwndbg을 설치해도 되지만,  
시간도 오래 걸리고 의존성 문제로 뜯어고칠 부분이 많으니 굳이 추천하진 않는다.   

그리고 분석용이 실습용 환경과 차이가 있는 경우가 종종 있다.  
예: Double Free Bug - tcache-dup (실제 서버 실습 환경에서는 free() 중복 처리 X)

그러니 실습용 도커로 실행파일을 돌려보고 분석하는 걸 추천한다.  

<br>

### 분석용 pwndbg 포함 도커 예시 (ubuntu 18.04)   

```Docker
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

```bash
IMAGE_NAME=ubuntu1804 CONTAINER_NAME=my_container; \
docker build . -t $IMAGE_NAME; \
docker run -d -t --privileged --name=$CONTAINER_NAME $IMAGE_NAME; \
docker exec -it -u root $CONTAINER_NAME bash
```

<br>

### 실습용 Docker 파일 예시 (ubuntu 18.04)  

```Docker
FROM ubuntu:18.04@sha256:ceed028aae0eac7db9dd33bd89c14d5a9991d73443b0de24ba0db250f47491d2

ENV user tcache_poison
ENV chall_port 7182

RUN apt-get update
RUN apt-get -y install socat

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
CMD while :; do socat -T 30 TCP-LISTEN:$chall_port,reuseaddr,fork EXEC:/home/$user/$user ; done
```
  
### 쉘로 진입 (socat 사용)  

```
docker build -t my_chall .
docker run -it --rm --name my_container my_chall bash
```

### 문제가 의도한 방법? (추천 X) 

실습환경 도커파일을 보면 아래처럼 로컬에서 주고받길 원하는 것 같지만 ..   
아래 명령어로 문제를 풀게 되면 노트북이 많이 고통스러워 한다.   

```bash
 docker run -it --rm --name my_container -p 7182:7182 my_chall
```
<br>

**payload 기본 양식 (추천 X)**

```python
from pwn import *

p = remote('localhost', 7182)

# libc 파일을 .py와 같은 폴더에 두고, 
libc = ELF('./libc-2.27.so')


~
(payload 작성 & send)
~


p.interactive()

```

<br>

### 추천하는 방법  

그래서 나는 그냥 분석용 pwndbg 포함 도커에 우분투 버전만 고쳐가면서  
해당 쉘에서 vi 로 파일 편집 후 python3 ./py파일 로 실행한다.   

이러면 아무리 많이 먹어도 wsl + docker 2기가 정도가 최대이고 멈출 일이 없다.  

참고로 vs code 에서 wsl 로 들어가면 멈출 수도 있다.  
그러니까 그냥 vi 나 nano 깔아서 쓰자.  

<br>

**payload 기본 양식 (추천 O)**
```
from pwn import *

p = process('./tcache_poison', env={"LD_PRELOAD":"./libc-2.27.so"})
libc = ELF('./libc-2.27.so')

~
(payload 작성)
~


p.interactive()
```

환경이 다르니 `env={"LD_PRELOAD":"./libc-2.27.so"}` 꼭 명시해줘야 한다.  
libc 파일은 그때그때 맞는 파일로 바꿔서 적어넣음 된다.  

<br>

### WSL 설정   

만약 내 컴퓨터가 vmmemWSL 이 4GB 만 넘어도 강제 종료가 된다면  

wsl에서 `mnt/c/Users/<사용자이름>/.wslconfig` 에 아래를 추가해주면 된다. (초기 설정 시 .wslconfig 파일 생성)

저장 후 powershell 에서 `wsl --shutdown` 후 `wsl` 명령어로 들어가서 free -h 로 확인 가능하다.  


**이건 내가 해둔 설정**

```ini
[wsl2]
memory=8GB
processors=4
swap=2GB
```
