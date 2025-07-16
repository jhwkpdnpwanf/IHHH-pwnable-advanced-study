# Quiz: SECCOMP

**Q1. SECCOMP에서 지원하는 모드는?**

**정답: Strict Mode**  

<br>

**Q2. 다음 코드는 두 가지의 SECCOMP 리스트 중 어떤 리스트인가요?**

```c
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0);
```

  

<br>


**정답 : ALLOW LIST**

**Q3. BPF와 연관없는 항목은?**

**정답: BPF_PULL**  

<br>


**Q4. 지문 설명에 해당하는 모드는 무엇인가요?**

**정답: Strict Mode**  

<br>
