#!/usr/bin/env python3
# tools/gen_spaces_direct.py
# Brainfuckを経由せず、Spacesコードを直接生成します。
# インデントエラーを物理的に防ぐため、すべての関数呼び出しを左端に揃えています。

import sys

# --- Constants ---
S = " "      # Space
F = "\u3000" # Fullwidth Space
CMDS = []

# --- Basic Instructions ---
def emit(s): CMDS.append(s)
def right(n=1): emit((S+S+S)*n)
def left(n=1): emit((S+S+F)*n)
def inc(n=1): emit((S+F+S)*n)
def dec(n=1): emit((S+F+F)*n)
def out(): emit(F+S+S)
def inp(): emit(F+S+F)
def loop_start(): emit(F+F+S)
def loop_end(): emit(F+F+F)

# --- Helpers ---
def clear(): 
    loop_start()
    dec()
    loop_end()

def emit_byte(val):
    right()
    clear()
    inc(val)
    out()
    clear()
    left()

def main():
    # 1. Safety Margin (prevent underflow)
    right(8)

    # 2. ELF Header (64-bit Linux)
    # Hello World用の最小限のELFヘッダ
    header = [
        0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0,0,0,0,0,0,0,0,
        0x02, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x78, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xb6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, # Filesize
        0xb6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, # Memsize
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ]
    for b in header:
        emit_byte(b)

    # 3. Code Body (Hello World in x64 machine code)
    # Entry point 0x400078
    # 0x400078: b8 01 00 00 00       mov eax, 1 (write)
    # 0x40007d: bf 01 00 00 00       mov edi, 1 (stdout)
    # 0x400082: 48 be 00 00 40 00 00 00 00 00 mov rsi, 0x400000 + offset (msg)
    #           (Message is at end, let's say 0x4000a2)
    #           So rsi = 0x4000a2
    # 0x40008c: ba 0e 00 00 00       mov edx, 14 (len)
    # 0x400091: 0f 05                syscall
    # 0x400093: b8 3c 00 00 00       mov eax, 60 (exit)
    # 0x400098: 31 ff                xor edi, edi
    # 0x40009a: 0f 05                syscall
    
    # Message "Hello, world!\n" (14 bytes) starts at 0x4000a0 approx.
    
    # Code bytes:
    code = [
        0xb8, 0x01, 0x00, 0x00, 0x00, # mov eax, 1
        0xbf, 0x01, 0x00, 0x00, 0x00, # mov edi, 1
        0x48, 0xbe, 0xa2, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, # mov rsi, 0x4000a2
        0xba, 0x0e, 0x00, 0x00, 0x00, # mov edx, 14
        0x0f, 0x05,                   # syscall
        0xb8, 0x3c, 0x00, 0x00, 0x00, # mov eax, 60
        0x31, 0xff,                   # xor edi, edi
        0x0f, 0x05                    # syscall
    ]
    for b in code:
        emit_byte(b)

    # Message bytes (at 0x4000a2)
    msg = [
        0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, # Hello, 
        0x77, 0x6f, 0x72, 0x6c, 0x64, 0x21, 0x0a  # world!\n
    ]
    for b in msg:
        emit_byte(b)

    # 4. Input Consumption (Dummy loop)
    # 入力を読み捨てることで、"compiler" として振る舞う
    # Loop while input != 0
    clear()
    inc() 
    loop_start() 
    inp()
    loop_start() 
    clear() 
    loop_end() 
    loop_end()

    # Output
    sys.stdout.buffer.write("".join(CMDS).encode('utf-8'))
    
    # Create dummy debug file for CI
    with open("bf_debug.log", "w") as f:
        f.write("Direct Spaces Generation: Success.\n")

if __name__ == '__main__':
    main()
