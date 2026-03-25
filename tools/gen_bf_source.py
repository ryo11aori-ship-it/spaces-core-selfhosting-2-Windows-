#!/usr/bin/env python3
# tools/gen_bf_source.py
# Generates "compiler_linear.bf"
# This BF program, when run, emits an ELF binary corresponding to a linear BF compiler.

import sys

def main():
    # BF Optimization State
    current_val = 0
    
    bf_code = []
    
    def emit_byte(target):
        nonlocal current_val
        diff = target - current_val
        
        if diff > 0:
            bf_code.append("+" * diff)
        elif diff < 0:
            bf_code.append("-" * abs(diff))
        
        bf_code.append(".")
        current_val = target

    def emit_bytes(bytes_list):
        for b in bytes_list:
            emit_byte(b)

    # --- 1. Header Logic ---
    # We output the ELF Header immediately.
    load_addr = 0x400000
    header_len = 120
    total_size = 500 # p_filesz
    
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
        *p64(total_size), *p64(0x10000), *p64(0x1000)
    ]
    
    emit_bytes(header + prog_header)
    
    # Init Code: mov rbx, 0x402000
    emit_bytes([0x48, 0xc7, 0xc3, 0x00, 0x20, 0x40, 0x00])
    
    # --- 2. Main Logic (Written in BF) ---
    # Read Char -> Check Type -> Emit Machine Code
    
    # Reset current cell to 0 for logic
    emit_byte(0) 
    
    # Logic Structure in BF:
    # ,[
    #   Copy C0 to C1
    #   Check C1 == '+'
    #   If match: Emit bytes
    #   ...
    #   Input Next (,)
    # ]
    
    # Since we are generating BF, we just append the strings directly.
    # Note: 'emit_byte' tracks the *output* logic. 
    # The *logic* of the compiler is static strings below.
    # But wait, the BF code above *outputs* the header.
    # Now we need BF code that *is* the loop logic.
    
    # Reset optimization state for the "Code Generation" part?
    # No, the BF code itself is continuous.
    
    # To output `+` character from the BF program? No.
    # The BF program *is* the compiler.
    # The previous `emit_byte` calls generated BF code that *prints* the header.
    # Now we need to generate BF code that *reads input and prints code*.
    
    # Reset cell to 0 before starting logic
    bf_code.append("[-]") 
    current_val = 0
    
    # Start Loop: , [
    bf_code.append(",[")
    
    # Helper to generate "Check char and emit bytes" in BF
    # Assumes we are at C0 (Input).
    # Uses C1, C2 as scratch.
    def add_check(char, bytes_to_emit):
        # Copy C0 to C1
        bf_code.append(">[-]>[-]<<[>+>+<<]>>[-<<+>>]<<")
        # Subtract char from C1
        bf_code.append(">" + ("-" * ord(char)) + "")
        # Check C1 is 0. Result in C2.
        # Temp C3.
        # C2=1. If C1!=0 C2=0.
        bf_code.append(">[-]+< [ >[-]< [-] ] >")
        # Now C2 is 1 if match, 0 if not.
        # If C2:
        bf_code.append("[")
        
        # Emit the machine code bytes!
        # This requires `.` output.
        # We need a cell to output from. Let's use C3.
        bf_code.append(">") # at C3
        curr = 0 # Local optimizer for C3
        for b in bytes_to_emit:
            diff = b - curr
            if diff > 0: bf_code.append("+" * diff)
            elif diff < 0: bf_code.append("-" * abs(diff))
            bf_code.append(".")
            curr = b
        bf_code.append("[-]") # Clear C3
        
        # Clear C2 to exit if
        bf_code.append("<[-]")
        bf_code.append("]")
        # Back to C0
        bf_code.append("<<")

    # > (62)
    add_check('>', [0x48, 0xff, 0xc3])
    # < (60)
    add_check('<', [0x48, 0xff, 0xcb])
    # + (43)
    add_check('+', [0xfe, 0x03])
    # - (45)
    add_check('-', [0xfe, 0x0b])
    # . (46)
    add_check('.', [0xb8, 0x01, 0x00, 0x00, 0x00, 0xbf, 0x01, 0x00, 0x00, 0x00, 0x48, 0x89, 0xde, 0xba, 0x01, 0x00, 0x00, 0x00, 0x0f, 0x05])
    # , (44)
    add_check(',', [0xb8, 0x00, 0x00, 0x00, 0x00, 0xbf, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0xde, 0xba, 0x01, 0x00, 0x00, 0x00, 0x0f, 0x05])

    # Next Char
    bf_code.append(",]")

    # --- 3. Footer Logic ---
    # Output Exit Syscall and Padding
    # We are at C0 (0). Use C0 to print.
    current_val = 0 
    
    # Exit Syscall
    emit_bytes([0x48, 0x31, 0xff, 0xb8, 0x3c, 0x00, 0x00, 0x00, 0x0f, 0x05])
    
    # Padding (500 zeros)
    # Optimization: Just print 0 500 times.
    emit_byte(0)
    bf_code.append("." * 500)

    print("".join(bf_code))

if __name__ == "__main__":
    main()
