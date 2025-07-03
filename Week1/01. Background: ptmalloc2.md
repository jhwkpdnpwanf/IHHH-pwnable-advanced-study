# Background: ptmalloc2


### Memory Allocator (메모리 할당자)

- 프로그램 실행 중, 필요한 동적 메모리를 요청하고 관리해주는 모듈
- 주로 힙 영역을 관리한다.

<br>

### Memory Allocator 종류

- **Linux** → ptmalloc2
- **Google** → tcmalloc
- **Facebook** & **Firefox** → jemalloc

<br>

### ptcmalloc2

- glibc 에서 사용하는 기본 Memory Allocator
- 효율적으로 메모리를 관리하기 위해 구현되었다.
    - **메모리 낭비 방지**  :  메모리 할당 요청이 발생하면, 먼저 해제된 메모리 공간 중에서 재사용 가능한 공간을 탐색한다.
    - **빠른 메모리 재사용**  :  `tcache`와 `bin`을 통해 해제된 공간의 정보를 저장해두어, 빠르게 재사용할 수 있도록 한다.
    - **메모리 단편화 방지**  :  내부 단편화와 외부 단편화 문제를 줄이기 위해 정렬(Alignment), 병합(Coalescence), 분할(Split) 을 사용한다. 추가 내용은 아래에.
<br>

> **내부 단편화 (Internal Fragmentation)**
>- 할당한 메모리 공간의 크기에 비해 실제 데이터가 점유하는 공간이 적을 때 발생한다.
>
>**외부 단편화 (External Fragmentation)**  
>- 할당한 메모리 공간들 사이에 공간이 많아서 발생하는 비효율을 의미한다.


>**정렬, 병합, 분할 :**
>- **정렬** : 64비트 환경에서 메모리 공간을 16바이트 단위로 할당해준다.
>- **병합** : 특정 조건을 만족하면 해제된 공간들을 병합하기도 한다.
>- **분할** : 병합으로 생성된 큰 공간은, 같은 크기의 요청 혹은 작은 요청에 의해 분할되어 재사용된다.

<br>

### ptmalloc2의 객체   
- ptmalloc2는 `chunk`, `bin`, `tcache`, `arena` 를 주요 객체로 사용한다.
<br>

### **청크 (chunk)**  
- 작은 덩어리라는 뜻으로, ptmalloc이 할당한 메모리 공간을 의미한다.
- 헤더와 데이터로 구성된다.
    - **헤더** : 청크 관리에 필요한 정보를 담고 있다.
    - **데이터** : 사용자가 입력한 데이터가 저장된다.


<img src="https://github.com/user-attachments/assets/56cde69a-b97e-4a46-8dd5-2e6f246043d8" width=500>  

헤더는 청크의 상태를 나타내므로 사용 중인 청크의 헤더와 해제된 청크의 헤더는 구조가 조금 다르다.  
사용 중인 청크는 `fd`와 `bk`를 사용하지 않고, 그 영역에 사용자가 입력한 데이터를 저장한다.  
<br>

**청크 헤더의 각 요소**  
  
| 이름       | 크기     | 의미 |
|------------|----------|------|
| prev_size | 8바이트 | 인접한 직전 청크의 크기이다. 청크를 병합할 때 직전 청크를 찾는 데 사용된다. |
| size      | 8바이트 | 현재 청크의 전체 크기이다. 헤더 크기도 포함되며 16바이트 단위로 정렬된다. |
| flags     | 3비트   | `size`의 하위 3비트를 사용해 청크 상태를 나타낸다.<br>이 플래그를 활용하여 병합이 필요한지 판단한다. |
| fd        | 8바이트 | 연결 리스트에서 다음 청크를 가리킨다. 해제된 청크에서만 사용된다. |
| bk        | 8바이트 | 연결 리스트에서 이전 청크를 가리킨다. 해제된 청크에서만 사용된다. |


<br>

### bin

- 사용이 끝난 청크들이 저장되는 객체이다.
- 메모리의 낭비를 막고, 해제된 청크를 빠르게 재사용할 수 있게 한다.
- ptmalloc2 에서는 총 128개이고 구조는 아래와 같다.
    - `smallbin` : 62개
    - `largebin` : 63개
    - `unsortedbin` : 1개
    - `사용 X` : 2개

<img src="https://github.com/user-attachments/assets/66033911-c22d-474d-9e42-bd10d50bd581" width=400>  


**smallbin**

- 원형 이중 연결 리스트이다.
- 32바이트 이상 ~ 1024바이트 미만
- FIFO (선입선출) 방식
- 청크를 추가하거나 꺼낼 때 연결고리를 끊는 과정이 필요하다. (`unlink` 과정)
- smallbin의 청크들은 ptmalloc의 병합 대상이다.
- 메모리상에서 인접한 두 청크가 해제되어 있고, smallbin에 들어있으면 이 둘은 병합된다. 
(`consolidation` 과정)

**fastbin**

- 단일 연결 리스트이다.
- 32바이트 이상 ~ 128바이트 미만 (In Linux)
- LIFO (후입선출) 방식
- 청크를 꺼낼 꺼낸 청크의 앞과 뒤를 연결하는 `unlink` 과정을 수행하지 않아도 된다.
- 서로 병합되지 않는다. 그래서 청크 간 병합에 사용되는 연산을 아낄 수 있다.

**largebin**

- 이중 연결 리스트
- 1024바이트 이상
- best-fit 기반 탐색
- 재할당 과정에서 `unlink`도 동방된다.
- largebin의 청크들은 병합 대상이다.

**unsortedbin**  
- 원형 이중 연결 리스트
- 크기 구분 X (모든 크기)
- 할당 요청 크기에 따라 탐색 순서가 다르다.
    - smallbin 크기 → fastbin, smallbin 탐색 이후 unsortedbin 탐색
    - largebin 크기 → unsortedbin 먼저 탐색
- 청크 해제 후 비슷한 크기 청크를 바로 할당하면 청크 분류에 낭비되는 비용을 없앨 수 있다.
- 한번에 여러 청크들을 연속적으로 해제하는 경우에도 해제하면서 병합하고 재분류하는 과정의 비용을 줄일 수 있다.

<br>

### arena

- fastbin, smallbin, largebin 등의 정보를 모두 담고 있는 객체이다.
- 멀티 쓰레드 환경에서 레이스 컨디션을 막기 위해 arena에 접근할 때 arena에 락을 적용한다.
- 단, 락은 쓰레드를 무제한으로 대기시키기 때문에 Deadlock 과 같은 문제가 발생할 수도 있다.
- 병목 현상을 피하기 위해 최대 64개의 arena를 생성할 수 있게 한다.

> **레이스 컨디션 (Race Condition)**
어떤 공유 자원을 여러 쓰레드나 프로세스에서 접근할 때 생기는 오동작이다.
> 

<br>

### tcache (thread local cache)

- 각 쓰레드에 독립적으로 존재하는 로컬 메모리 캐시이다.
- 각 쓰레드는 최대 64개 tcache를 가지며 각 최대 7개의 청크를 LIFO 방식으로 관리한다.
- 속도는 빠르지만 병합이 없고 보안 검사가 약해, 익스플로잇에 자주 악용된다.

<br>

### 앞으로 실습 환경 구축

- **실습 환경 :** Ubuntu 18.0.4 64bit(Glibc 2.27)

**Ubuntu 18.04 64-bit(Glibc 2.27) 실습 환경 Dockerfile**

```bash
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
RUN gem install one_gadget

WORKDIR /root
```

<br>

**도커 이미지 빌드/컨테이너 실행/셸 실행 명령어**

```bash
$ IMAGE_NAME=ubuntu1804 CONTAINER_NAME=my_container; \
docker build . -t $IMAGE_NAME; \
docker run -d -t --privileged --name=$CONTAINER_NAME $IMAGE_NAME; \
docker exec -it -u root $CONTAINER_NAME bash
```
