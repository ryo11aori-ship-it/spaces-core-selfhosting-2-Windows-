# Spaces Grammar Definition

## Abstract Syntax
Program ::= Instruction*
Instruction ::= 
    | PTR_INC  ( > )
    | PTR_DEC  ( < )
    | VAL_INC  ( + )
    | VAL_DEC  ( - )
    | OUTPUT   ( . )
    | INPUT    ( , )
    | JMP_FWD  ( [ )
    | JMP_BCK  ( ] )

## Concrete Syntax (Encoding)
The source code consists of a sequence of Bits encoded by Space characters.
- Bit 0: U+0020 (Half-width Space)
- Bit 1: U+3000 (Full-width Space)

Instruction Mapping (3-bit big-endian):
> : 000 (S S S)
< : 001 (S S F)
+ : 010 (S F S)
- : 011 (S F F)
. : 100 (F S S)
, : 101 (F S F)
[ : 110 (F F S)
] : 111 (F F F)
