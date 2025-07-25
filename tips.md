# 도움 링크들

###  x86_64 아키텍처 시스템 콜 번호 & 인자  
https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/

<br>

### 리눅스 명령어, 시스템 콜 메뉴얼 페이지 + 비슷한 함수까지 
https://man7.org/ 

<br>

### 리눅스 명령어, 시스템 콜 메뉴얼 페이지
https://linux.die.net/

<br>
<br>

### libc 파일 설정

```bash
export LD_PRELOAD=$(realpath ./libc-2.27.so)
```

<br>
<br>

### patchelf로 로더 패치

로더 버전이 맞는지 확인할 때 명령어이다.  
같은 디렉토리안에 있는 .so 파일과 비교할 때이다. (ex. `ld-2.27.so`)   

```bash
root@c6d07003e850:~/rtld_global# md5sum ld-2.27.so
ecedcc8d1cac4f344f2e2d0564ff67ab  ld-2.27.so

root@c6d07003e850:~/rtld_global# md5sum /lib64/ld-linux-x86-64.so.2
bd1331eea9e034eb3d661990e25037b7  /lib64/ld-linux-x86-64.so.2

root@c6d07003e850:~/rtld_global# readelf -s ld-2.27.so | grep " _rtld_global@"
    25: 0000000000228060  3960 OBJECT  GLOBAL DEFAULT   21 _rtld_global@@GLIBC_PRIVATE
    
root@c6d07003e850:~/rtld_global# readelf -s /lib64/ld-linux-x86-64.so.2 | grep " _rtld_global@"
    25: 000000000022a060  3960 OBJECT  GLOBAL DEFAULT   21 _rtld_global@@GLIBC_PRIVATE
```

추가로 vmmap으로도 확인가능하다.  

이렇게 다른 것을 확인했다면   
```bash
patchelf --set-interpreter ./ld-2.27.so ./ow_rtld
```
이렇게 바꿔줄 수 있다.  

<br>
<br>

### 덤프 코어 파일 생성 & 확인
```bash
ulimit -c unlimited
ulimit -a
```

`core file size   (blocks, -c) unlimited` 를 unlimited 로 만들어주기.  

- 파일 생성 위치 : `C:\Users\<사용자 파일>\AppData\Local\Temp\wsl-crashes`

<br>

```bash
 gdb ./실행파일 -c ./덤프코어파일
```
gdb 로 실행해주고 glibc 파일을 설치해준다.  
설치를 했다면,  

<br>

```bash
pwndbg> dir ./glibc-2.35
Source directories searched: /root/./glibc-2.35:$cdir:$cwd
pwndbg> tui enable
```
이런식으로 tui 모드로 진입이 가능하다.  
<br>

**예시 사진**  
<img width="1407" height="1122" alt="image (29)" src="https://github.com/user-attachments/assets/a5c5675f-dfd4-49f1-9461-1779f5173a8f" />   

이렇게 문제가 있었던 곳이 표시가 된다.   
