import sys

# Stage 3: Self-Hosted Identity Translator (Echo Program)
# Logic: ,[.,]

def main():
    bf_code = ",[.,]"
    S, F = " ", "\u3000"
    mapping = {
        ',': F + S + F,
        '[': F + F + S,
        '.': F + S + S,
        ']': F + F + F
    }
    spaces_code = "".join([mapping[c] for c in bf_code])
    print(spaces_code, end='')

if __name__ == "__main__":
    main()
