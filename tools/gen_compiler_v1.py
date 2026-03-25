#!/usr/bin/env python3
# tools/gen_compiler_v1.py
# Level 0.9: Unrolled Logic Compiler (Fixed Indentation)
#
# Generates a Spaces program that:
# 1. Emits ELF Header.
# 2. Repeats 64 times: Read char -> If '+' emit inc -> If '-' emit dec.
# 3. Emits Exit syscall.
# 4. Pads to target size dynamically.

import sys

# --- Spaces Ops ---
S = " "
F = "\u3000"

def emit(s): sys.stdout.write(s + "\n")
def right(n=1): emit((S+S+S)*n)
def left(n=1): emit((S+S+F)*n)
def inc(n=1): emit((S+F+S)*n)
def dec(n=1): emit((S+F+F)*n)
def out(): emit(F+S+S)
def inp(): emit(F+S+F)
def loop_open(): emit(F+F+S)
def loop_close(): emit(F+F+F)
def clear(): loop_open(); dec(); loop_close()

# --- Memory Layout ---
# C0: Input Buffer / Cursor
# C1: Scratch
# C2: Scratch
# C3: Match Flag
# C7: Output Byte Counter

def emit_byte_tracked(val):
    # Emit byte val and increment C7
    # Temp move to C8 to emit
    right(8); clear(); inc(val); out(); clear(); left(8)
    # Inc Counter C7
    right(7); inc(); left(7)

def emit_bytes(vals):
    for v in vals: emit_byte_tracked(v)

def main():
    # 1. ELF Header (Total Target: 300 bytes)
    total_size = 300
    load_addr = 0x400000
    header_len = 120
    
    def p64(v): return list(v.to_bytes(8, "little"))
    def p32(v): return list(v.to_bytes(4, "little"))

    header = [
        0x7f,0x45,0x4c,0x46,0x02,0x01,0x01,0x00,0,0,0,0,0,0,0,0,
        0x02,0x00,0x3e,0x00,0x01,0x00,0x00,0x00,
        *p64(load_addr + header_len), *p64(64), *p64(0), *p32(0),
        0x40,0x00,0x38,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    ]
    prog_header = [
        0x01,0x00,0x00,0x00,0x07,0x00,0x00,0x00,
        *p64(0), *p64(load_addr), *p64(load_addr),
        *p64(total_size), *p64(total_size), *p64(0x1000)
    ]
    
    # Initialize Logic
    right(10) # Safety margin
    emit_bytes(header + prog_header)
    
    # Init Code: xor rbx, rbx (48 31 db)
    emit_bytes([0x48, 0x31, 0xdb])
    
    # 2. Unrolled Logic (Repeat 64 times)
    # Reads input chars one by one and emits code.
    
    for _ in range(64):
        # Read char to C0
        clear(); inp()
        
        # --- Check '+' (43) ---
        # Copy C0 -> C1
        right(1); clear(); left(1)
        loop_open(); dec(); right(); inc(); right(); inc(); left(2); loop_close()
        right(2); loop_open(); left(2); inc(); right(2); dec(); loop_close(); left(2)
        
        # Sub 43 from C1
        right(); dec(43)
        
        # Is C1 Zero? (If Zero, C3 = 1)
        right(2); clear(); inc(); left(2) # C3=1
        loop_open(); right(2); clear(); left(2); clear(); loop_close() # If C1!=0, C3=0
        
        # If Match (C3==1), Emit `inc rbx`
        right(2)
        loop_open()
        # Emit logic inside loop (runs once)
        left(3) # Back to C0 relative
        emit_byte_tracked(0x48); emit_byte_tracked(0xff); emit_byte_tracked(0xc3)
        right(3) # Back to C3
        clear() # clear flag
        loop_close()
        left(2) # Back to C1
        left()  # Back to C0

        # --- Check '-' (45) ---
        # Copy C0 -> C1
        right(1); clear(); left(1)
        loop_open(); dec(); right(); inc(); right(); inc(); left(2); loop_close()
        right(2); loop_open(); left(2); inc(); right(2); dec(); loop_close(); left(2)
        
        # Sub 45 from C1
        right(); dec(45)
        
        # Is C1 Zero?
        right(2); clear(); inc(); left(2)
        loop_open(); right(2); clear(); left(2); clear(); loop_close()
        
        # If Match, Emit `dec rbx`
        right(2)
        loop_open()
        left(3)
        emit_byte_tracked(0x48); emit_byte_tracked(0xff); emit_byte_tracked(0xcb)
        right(3)
        clear()
        loop_close()
        left(2)
        left() # Back to C0

    # 3. Exit Code
    # mov edi, ebx; mov eax, 60; syscall
    emit_bytes([0x89, 0xdf, 0xb8, 0x3c, 0x00, 0x00, 0x00, 0x0f, 0x05])
    
    # 4. Padding
    # Pad until C7 == 300
    right(7) # Move to counter
    dec(300)
    loop_open()
    inc(300) # Restore
    left(7)  # Go to emit pos
    # Emit 0
    right(8); clear(); out(); left(8); right(7); inc() # Manual emit 0 & inc C7
    left(7)
    right(7); dec(300) # Check again
    loop_close()
    
    # Done

if __name__ == "__main__":
    main()
