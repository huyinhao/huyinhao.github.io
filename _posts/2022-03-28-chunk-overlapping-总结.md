---
layout: post
title: Chunk overlapping 总结 
subheading: glibc 2.23, glib 2.27
author: dayfly
categories: pwn
banner:
  video: null
  loop: true
  volume: 0.8
  start_at: 8.5
  image: https://images.pexels.com/photos/1647177/pexels-photo-1647177.jpeg?cs=srgb&dl=pexels-damon-hall-1647177.jpg&fm=jpg
  opacity: 0.618
  background: "#000"
  height: "100vh"
  min_height: "38vh"
  heading_style: "font-size: 5em; font-weight: bold; text-decoration: none; min-width: 1100px"
  subheading_style: "color: gold"
tags: [pwn, heap, chunk overlapping, set]
# sidebar: []
---

## Off By One

通常的利用思路是覆盖被溢出堆块的下一个堆块`size`域的最低一字节，可以扩展堆块，也可以缩减堆块，只是后者对数据构造的要求更高一些

### 后向扩展

- 这里称被溢出堆块的下一个堆块为**target**堆块
- 通过`off by one`漏洞可以轻易地让**target**堆块的`size`变大，即可让**target**包含高地址相邻堆块的内容
- 后续的利用可以配合`UAF`，`Unlink`攻击的利用

### 例题：

- [HITCON Trainging lab13][4]

## Off By Null

- 仍然存在单字节溢出，只是溢出的值为`'\0'`，可以缩减堆块
- 更常规地是将**target**堆块的`prev_inuse`比特清零，达到伪造被溢出堆块被free的状态
- 后续构造`prev_size`和fake_chunk进行`unlink`攻击，从而达到堆块重叠

### 例题

- [poison null byte][1]
- [overlapping chunks][2]

## mmap overlapping chunks 

### 例题

- [mmap_overlapping_chunks.c][3]


  [1]: https://github.com/shellphish/how2heap/blob/master/glibc_2.27/poison_null_byte.c
  [2]: https://github.com/shellphish/how2heap/blob/master/glibc_2.27/overlapping_chunks.c
  [3]: https://github.com/shellphish/how2heap/blob/master/glibc_2.27/mmap_overlapping_chunks.c
  [4]: https://github.com/scwuaptx/HITCON-Training/tree/master/LAB/lab13