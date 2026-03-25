# Tape Data Encoding Specification

Target: To represent a Spaces program as a sequence of bytes on the memory tape.

## Format
[MAGIC_HEADER] [INSTRUCTION_SEQUENCE] [TERMINATOR]

## 1. Magic Header
Sequence of 3 bytes to verify format: `S`, `P`, `A` (0x53, 0x50, 0x41)

## 2. Instruction Schema
Each instruction is represented by a single byte code followed by optional operands.

| Instruction | Opcode (Hex) | Operand |
|-------------|--------------|---------|
| PTR_INC (>) | 0x01         | None    |
| PTR_DEC (<) | 0x02         | None    |
| VAL_INC (+) | 0x03         | None    |
| ...         | ...          | ...     |
| JMP_FWD ([) | 0x07         | 2-byte Offset (Big Endian) |
| JMP_BCK (]) | 0x08         | 2-byte Offset (Big Endian) |

## 3. Separator (Optimization for readability)
Between instructions, a specific separator (e.g., 3 Full-width Spaces) may be inserted for tokenizer synchronization, though the binary opcode stream is packed.
*(Note: For strict bootstrap, packed binary is preferred for simplicity in the interpreter loop.)*
