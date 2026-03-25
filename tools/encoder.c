#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 Stage 1: Encoder Tool
 Converts Spaces source code into binary tape format.
 Format: [MAGIC: SPA] [OPCODES...] [EOF]
*/

// Spaces Characters (UTF-8)
// Half-width space (0x20) -> Bit 0
// Full-width space (0xE3 0x80 0x80) -> Bit 1

int is_full_space(unsigned char *s, int *idx) {
    if (s[*idx] == 0xE3 && s[*idx+1] == 0x80 && s[*idx+2] == 0x80) {
        *idx += 2; return 1;
    }
    return 0;
}

// 3-bit Opcode Map
// >(000) <(001) +(010) -(011) .(100) ,(101) [(110) ](111)
unsigned char get_opcode(int bits) {
    switch(bits) {
        case 0: return 0x01; // > INC_PTR
        case 1: return 0x02; // < DEC_PTR
        case 2: return 0x03; // + INC_VAL
        case 3: return 0x04; // - DEC_VAL
        case 4: return 0x05; // . OUT
        case 5: return 0x06; // , IN
        case 6: return 0x07; // [ JMP_FWD
        case 7: return 0x08; // ] JMP_BCK
    }
    return 0x00; // NOP
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input.spaces>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("File open error"); return 1; }

    // Read entire file
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *input = malloc(fsize + 1);
    fread(input, 1, fsize, f);
    fclose(f);
    input[fsize] = 0;

    // Output to stdout (Binary)
    // 1. Write Magic Header "SPA"
    putchar('S'); putchar('P'); putchar('A');

    // 2. Parse and Write Opcodes
    int bit_buf = 0;
    int bit_cnt = 0;
    
    for (int i = 0; i < fsize; i++) {
        int bit = -1;
        if (input[i] == 0x20) bit = 0;
        else if (input[i] == 0xE3) {
            if (is_full_space(input, &i)) bit = 1;
        }

        if (bit != -1) {
            bit_buf = (bit_buf << 1) | bit;
            bit_cnt++;
            if (bit_cnt == 3) {
                unsigned char op = get_opcode(bit_buf);
                if (op != 0) putchar(op);
                bit_buf = 0;
                bit_cnt = 0;
            }
        }
    }

    free(input);
    return 0;
}
