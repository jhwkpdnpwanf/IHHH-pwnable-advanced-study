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
