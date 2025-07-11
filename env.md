# 실습 환경 구축  

실습 환경을 구축하고, payload를 보내기까지 정말 많은 방법들이 있지만,  
내가 자주 쓰는 방법으로 소개해볼까 한다.  

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

### 공격코드 실행 전에   

실습환경 쉘에서 동작을 확인하고 분석한 뒤,  

아래 명령어를 쉘 외부에서 실행하면 된다.    

```bash
 docker run -it --rm --name my_container -p 7182:7182 my_chall
```

<br>

**payload 기본 양식**

```python
p = remote('localhost', 7182)

# libc 파일을 .py와 같은 폴더에 두고, 
libc = ELF('./libc-2.27.so')


~
(payload 작성 & send)
~


p.interactive()

```

<br>

### WSL 설정   

vmmemWSL 이 2GB 만 넘어도 강제 종료가 됐어서 따로 설정해줬다.   

wsl에서 `mnt/c/Users/<사용자이름>/.wslconfig` 에 아래를 추가해주면 된다. (초기 설정 시 .wslconfig 파일 생성)

저장 후 powershell 에서 `wsl --shutdown` 후 `wsl` 명령어로 들어가서 free -h 로 확인 가능하다.  



```ini
[wsl2]
memory=8GB
processors=4
swap=2GB
```
