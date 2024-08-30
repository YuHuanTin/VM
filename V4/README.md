如果第二条指令 为读 RAX ，则第一条指令写 al，ah，ax，eax，rax 都不能消除
如果第二条指令 为写 RAX， 则第一条指令写 al，ah，ax，eax，rax 都被消除

第二次写 任意，第一次有读 al、ah、ax、eax、rax 都不能被消除
第二次写 rax，第一次写 al、ah、ax、eax、rax 都被消除
第二次写 eax，第一次写 al、ah、ax、eax 都被消除
第二次写 ax ，第一次写 al、ah 都被消除
第二次写 ah ，第一次写 ah 都被消除
第二次写 al ，第一次写 al 都被消除

```cpp
for reg in regs from this_instruction:
    if this_instruction[reg] & ZYDIS_OPERAND_ACTION_MASK_READ:
        continue;
```

label1: 对于 inst2 遍历所有的寄存器和寄存器操作，如果某一寄存器操作为写，则

- 对于该'写'的寄存器，获取同类寄存器列表，然后开始往前找指令，找到 inst1 指令含有同类寄存器的指令
    - 如果 inst1 包含多个同类寄存器，则先全部取出，然后
    - 如果有一寄存器为读操作，退出到 label1
    - 如果是读写则去除写操作并且退出到 label1
    - 如果是仅仅为写的，删除该写操作，继续往前找



