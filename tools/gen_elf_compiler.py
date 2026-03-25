import sys

# Stage 8: Native ELF Compiler Generator (Fixed)
# Generates a Spaces program that outputs a valid "Hello World" ELF binary.
# Fixes: Corrects FileSize in ELF header to prevent Segmentation Fault.

def main():
    bf = []
    def emit(s): bf.append(s)

    # --- ELF Header & Program Header (x86-64 Linux) ---
    # Entry point: 0x400078
    # Total File Size goal: ~176 bytes (0xB0) to cover Header + Code + Msg
    
    header = [
        # ELF Header (64 bytes)
        0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0,0,0,0,0,0,0,0, 
        0x02, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00, 
        0x78, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, # Entry: 0x400078
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00, 
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        
        # Program Header (56 bytes)
        0x01, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, # LOAD, RWX
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, # Offset 0
        0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, # VAddr 0x400000
        0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 
        
        # FIX: FileSize must not exceed actual file size (~170 bytes)
        # We set it to 0xB0 (176 bytes) and will pad the file to match.
        0xb0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, # FileSize = 176
        0xb0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, # MemSize = 176
        
        0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00  # Align
    ]
    
    # Machine Code for Hello World (x64 Linux)
    # Start Address: 0x400078
    code_hex = [
        # mov eax, 1 (write)
        0xb8, 0x01, 0x00, 0x00, 0x00,
        # mov edi, 1 (stdout)
        0xbf, 0x01, 0x00, 0x00, 0x00,
        
        # mov rsi, msg_addr
        # Code start: 0x400078. 
        # Code length so far: 10 bytes.
        # This instruction: 10 bytes.
        # Remaining code: 5 + 2 + 5 + 3 + 2 = 17 bytes.
        # Total Code Size = 37 bytes.
        # Msg Addr = 0x400078 + 37 = 0x40009D
        0x48, 0xbe, 0x9d, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
        
        # mov edx, 13 (len: "Hello World!\n")
        0xba, 0x0d, 0x00, 0x00, 0x00,
        # syscall
        0x0f, 0x05,
        
        # mov eax, 60 (exit)
        0xb8, 0x3c, 0x00, 0x00, 0x00,
        # xor rdi, rdi (status 0)
        0x48, 0x31, 0xff,
        # syscall
        0x0f, 0x05
    ]
    
    # Message: "Hello World!\n" (13 bytes)
    msg = [72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100, 33, 10] 
    
    # Combine Header + Code + Msg
    full_binary = header + code_hex + msg
    
    # Pad with zeros to match FileSize (0xB0 = 176)
    padding = 176 - len(full_binary)
    if padding > 0:
        full_binary += [0] * padding

    # Generate Spaces Code
    for b in full_binary:
        if b == 0:
            emit('.')
        else:
            emit('+' * b + '. [-]')

    # Convert to Spaces (UTF-8 Output)
    S, F = " ", "\u3000"
    mapping = {'>':S*3, '<':S*2+F, '+':S+F+S, '-':S+F+F, '.':F+S+S, ',':F+S+F, '[':F*2+S, ']':F*3}
    full_bf = "".join(bf)
    
    output_str = "".join([mapping.get(c, '') for c in full_bf])
    sys.stdout.buffer.write(output_str.encode('utf-8'))

if __name__ == "__main__":
    main()
