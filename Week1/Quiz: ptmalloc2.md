# Quiz: ptmalloc2


**Q1. 메모리 파편화를 막기위해 연속된 fastbin의 청크는 병합된다.**  
**답 : X**

<br>

**Q2. smallbin의 청크를 재할당할 때, unlink과정을 수행해야 한다.**  
**답 : O**

<br>

**Q3. 청크를 재할당 할 때, bin를 먼저 비운 뒤 tcache에서 청크를 꺼낸다.**  
**답 : X**

<br>

**Q4. largebin에 보관할 수 있는 청크의 갯수는 10개로 제한된다.**  
**답 : X**

<br>
