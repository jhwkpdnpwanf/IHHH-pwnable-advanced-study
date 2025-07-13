# Quiz: Format String Bug

**Q1. 아래 코드에서 printf(userinput);을 안전하게 수정하시오.**

```c
char userinput[0x20] = {0, };
scanf("%31s", userinput)
printf(userinput); <-
```

**정답: puts(userinput);과 printf("%s", userinput); 모두 안전하다.**
