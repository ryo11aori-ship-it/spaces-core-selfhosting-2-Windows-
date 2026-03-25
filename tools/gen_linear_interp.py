import sys

def main():
    # Helper functions
    def move(n): return ">"*n if n>0 else "<"*abs(n)
    def add(n): return "+"*n
    def sub(n): return "-"*n
    def loop(content): return "[" + content + "]"
    def clear(): return "[-]"

    # --- Linear Interpreter Logic ---
    # Memory Layout:
    # Cell 0: Temp / Working
    # Cell 1: Current Opcode (Input Buffer)
    # Cell 2+: Virtual Tape (Target Program's Memory)
    
    bf = ""
    
    # 1. Header Skip (Read 'S', 'P', 'A' -> discard)
    bf += move(1) + "," + "," + "," 
    
    # 2. Main Loop: Read Opcode -> Execute -> Repeat
    bf += "," # Read first opcode into Cell 1
    bf += loop(
        # Check Opcode in Cell 1
        
        # Case: + (0x03)
        sub(3)
        + loop( # If not 0x03
            # Case: - (0x04) -> check offset from 0x03 is 1
            sub(1)
            + loop( # If not 0x04
                # Case: . (0x05)
                sub(1)
                + loop( # If not 0x05
                     clear() # Unknown op, ignore
                )
                # Action for . (Output Virtual Tape at Cell 2)
                + move(1) + "." + move(-1)
                + clear()
            )
            # Action for - (Dec Virtual Tape at Cell 2)
            + move(1) + sub(1) + move(-1)
            + clear()
        )
        # Action for + (Inc Virtual Tape at Cell 2)
        + move(1) + add(1) + move(-1)
        
        # Read Next Opcode
        + ","
    )

    # --- Convert to Spaces ---
    S, F = " ", "\u3000"
    mapping = {'>':S*3, '<':S*2+F, '+':S+F+S, '-':S+F+F, '.':F+S+S, ',':F+S+F, '[':F*2+S, ']':F*3}
    
    res = ""
    for c in bf:
        if c in mapping: res += mapping[c]
    
    print(res, end='')

if __name__ == "__main__":
    main()
