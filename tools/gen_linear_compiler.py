import sys

# Stage 9: Linear Native Compiler Generator (Instruction Encoding Fix)
# Generates a Spaces program that:
# 1. Emits ELF Header (64KB).
# 2. Translates Source to CORRECT x64 Machine Code (Fixed ModRM byte).
# 3. PADS the output with ~64KB of zeros.

def main():
    bf = []
    def emit(s): bf.append(s)

    # --- ELF Header (x86-64 Linux) ---
    header = [
        0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0,0,0,0,0,0,0,0, 
        0x02, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00, 
        0x78, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00, 
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        # PHeader
        0x01, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 
        # FileSize 64KB
        0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 
        # MemSize 64KB
        0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 
        # Alignment 4KB
        0x00, 16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 
    ]
    
    # Emit Header
    for b in header:
        if b: emit('+'*b + '. [-]')
        else: emit('.')

    # Runtime Init: mov r13, 0x408000
    init_code = [0x49, 0xbd, 0x00, 0x80, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00]
    for b in init_code:
        if b: emit('+'*b + '. [-]')
        else: emit('.')

    # --- Main Compilation Loop ---
    emit(',[') 
    
    def emit_bytes(bs):
        for b in bs:
            emit('>' + '+'*b + '. [-] <')

    # Copy C0 -> C1 safely
    emit('>[-]>[-]<< [>+>+<<-] >> [<<+>>-] <') 
    
    # Check function
    def check(val, bytes_hex):
        emit('-'*val) 
        emit('>[-]+<') 
        emit('[>[-]<[-]]') 
        emit('>') 
        emit('[') 
        emit_bytes(bytes_hex)
        emit('[-]]') 
        emit('<<') 
        emit('>[-]>[-]<< [>+>+<<-] >> [<<+>>-] <') 

    # Order check - FIXED HEX CODES
    # + (43): inc byte [r13]. Was 05 (RIP+), Now 45 (R13+disp8)
    check(43, [0x41, 0xfe, 0x45, 0x00]) 
    
    # - (45): dec byte [r13]. Was 0D (RIP+), Now 4D (R13+disp8)
    check(45, [0x41, 0xfe, 0x4d, 0x00]) 
    
    # . (46)
    check(46, [
        0xb8, 0x01, 0x00, 0x00, 0x00,
        0xbf, 0x01, 0x00, 0x00, 0x00,
        0x4c, 0x89, 0xee,
        0xba, 0x01, 0x00, 0x00, 0x00,
        0x0f, 0x05
    ]) 
    
    # > (62)
    check(62, [0x49, 0xff, 0xc5]) 
    # < (60)
    check(60, [0x49, 0xff, 0xcd]) 
    
    emit('< [-],]') 

    # --- Epilogue (Exit 0) ---
    exit_code = [0xb8, 0x3c, 0x00, 0x00, 0x00, 0x48, 0x31, 0xff, 0x0f, 0x05]
    for b in exit_code:
        if b: emit('+'*b + '. [-]')
        else: emit('.')

    # --- PADDING (64KB) ---
    emit('>>') 
    emit('[-]' + '+'*255) # C2 = 255
    emit('[') 
    emit('>') 
    emit('[-]' + '+'*255) # C3 = 255
    emit('[') 
    emit('>') 
    emit('.') # Print 0
    emit('<') 
    emit('-]') 
    emit('<') 
    emit('-]') 
    # Note: 255*255 is approx 65000. Close enough to fill gap.

    # Output
    S, F = " ", "\u3000"
    mapping = {'>':S*3, '<':S*2+F, '+':S+F+S, '-':S+F+F, '.':F+S+S, ',':F+S+F, '[':F*2+S, ']':F*3}
    full_bf = "".join(bf)
    sys.stdout.buffer.write("".join([mapping.get(c, '') for c in full_bf]).encode('utf-8'))

if __name__ == "__main__":
    main()
