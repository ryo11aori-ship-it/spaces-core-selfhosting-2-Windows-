import sys

# Stage 5: Native Self-Hosted Compiler (Spaces UTF-8 Source -> Spaces Binary)
# Fixed: IndentationError at line 51 (Standardized to 4 spaces).

def main():
    bf = []
    def emit(s): bf.append(s)
    
    # --- 1. Header (SPA) ---
    emit('+' * 0x53); emit('.'); emit('[-]')
    emit('+' * 0x50); emit('.'); emit('[-]')
    emit('+' * 0x41); emit('.'); emit('[-]')

    # --- Variables / Cell Layout ---
    # Cell 0: Input Char
    # Cell 1: Bit Buffer (accumulates bits)
    # Cell 2: Bit Count (0..3)
    # Cell 3: Temp / Copy
    # Cell 4: Flag / Copy-Temp
    
    # --- 2. Main Loop ---
    emit(',')
    emit('[') 

    # Helper: Check if Cell 0 == val. Result in Cell 4.
    def check_val(val):
        # We need to clear Temp(3) and Flag(4).
        emit('>>>[-]>[-]<<<<') # Clear 3, 4. Ptr=0
        
        # FIX: Non-destructive copy from 0 to 3 using 4 as temp.
        # 1. Move 0 -> 3 and 4
        emit('[>>>+>+<<<<-]') # Cell 0 becomes 0. 3 and 4 get value. Ptr=0.
        
        # 2. Restore 0 from 4
        emit('>>>>[<<<<+>>>>-]') # Move 4 -> 0. Ptr=4.
        emit('<<<<') # Ptr=0.
        
        # Now Cell 0 has original value, Cell 3 has copy, Cell 4 is 0.
        
        # Subtract val from 3
        emit('>>>') # Ptr=3
        emit('-' * val)
        
        # Check if 3 is 0. Result in 4.
        emit('>[-]+<') # Flag(4)=1. Ptr=3
        emit('[>-<[-]]') # If 3!=0, Flag(4)=0, Clear 3.
        emit('<') # Ptr=2
        emit('<<') # Ptr=0

    # Helper: Append Bit (0 or 1)
    def append_bit(bit_val):
        # Ptr=0.
        
        # 1. Buffer = Buffer * 2 + bit_val
        emit('>') # Ptr=1 (Buffer)
        emit('[>>>+<<<-]') # Move 1->4. Ptr=1
        emit('>>>') # Ptr=4
        emit('[<<<++>>>-]')   # Move 4->1 (Doubled). Ptr=4
        
        if bit_val == 1:
            emit('<<<+>>>')    # Add 1 to Buffer if bit is 1
            
        emit('<<<') # Ptr=1
        
        # 2. Count++
        emit('>') # Ptr=2 (Count)
        emit('+')
        
        # 3. Check if Count == 3
        # Copy Count(2) -> Temp(3), using Flag(4) as restore-temp
        emit('>[-]>[-]<<') # Clear 3, 4. Ptr=2
        emit('[>+>+<<-]')  # Move 2->3,4. Ptr=2
        emit('>>[<<+>>-]') # Move 4->2. Ptr=4
        emit('<') # Ptr=3 (Temp has Count)
        
        # Subtract 3
        emit('---') 
        
        # Check if 0. Flag in 4.
        emit('>[-]+<') # Flag(4)=1. Ptr=3
        emit('[>-<[-]]') # If 3!=0, Flag=0. Ptr=3
        
        # 4. If Flag(4) is 1, Output Opcode
        emit('>') # Ptr=4
        emit('[') 
        # Opcode = Buffer(1) + 1
        # We can destructively move Buffer(1) -> Temp(3) since we reset after.
        emit('<<<') # Ptr=1
        emit('[>>+<<-]') # Move 1->3. Ptr=1
        
        # Output
        emit('>>') # Ptr=3
        emit('+.') # Add 1 and Output
        emit('[-]') # Clear 3
        
        # Reset Count(2)
        emit('<[-]') # Clear 2
        
        # Clear Flag(4) to exit loop
        emit('>>[-]') # Ptr=4
        emit(']')
        
        # Return to 0
        emit('<<<<')

    # --- Logic Body ---
    
    # 1. Check for Space (0x20) -> Bit 0
    check_val(0x20)
    emit('>>>>') # Ptr=4 (Flag)
    emit('[')
    emit('[-]') # Clear Flag
    emit('<<<<') # Ptr=0
    append_bit(0)
    emit('>>>>') # Ptr=4
    emit(']')
    emit('<<<<') # Ptr=0

    # 2. Check for 0xE3 -> Bit 1 (and consume 2 bytes)
    check_val(0xE3)
    emit('>>>>') # Ptr=4 (Flag)
    emit('[')
    emit('[-]') # Clear Flag
    emit('<<<<') # Ptr=0
    
    # Consume 2 bytes (0x80, 0x80) from input
    emit(',') # Read byte 2 -> Cell 0
    emit(',') # Read byte 3 -> Cell 0
    
    append_bit(1)
    
    # Restore Cell 0 to 0 (it holds junk 0x80, main loop expects 0 at end of iter)
    emit('[-]')
    
    emit('>>>>') # Ptr=4
    emit(']')
    emit('<<<<') # Ptr=0

    # --- End Main Loop ---
    # Clear Cell 0
    emit('[-]')
    emit(',')
    emit(']')

    # Output
    S, F = " ", "\u3000"
    mapping = {'>':S*3, '<':S*2+F, '+':S+F+S, '-':S+F+F, '.':F+S+S, ',':F+S+F, '[':F*2+S, ']':F*3}
    
    full_bf = "".join(bf)
    print("".join([mapping.get(c, '') for c in full_bf]), end='')

if __name__ == "__main__":
    main()
