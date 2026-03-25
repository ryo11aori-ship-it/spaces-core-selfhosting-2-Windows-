/* src/ref/vm.c -- Spaces VM: execute SPA->Spaces as interpreter */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> /* isatty */
#include <sys/types.h>
#include <sys/stat.h>
/* Windows-specific headers if needed */
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

/* 64KB */
#define TAPE_SIZE 65536
#define MAX_FILE_SIZE 1048576 /* 1MB limit */

unsigned char tape[TAPE_SIZE];
int ptr = 0;

/* Spaces command set (3-bit encoding) */
typedef enum {
    SPC_RIGHT = 0,  /* > */
    SPC_LEFT  = 1,  /* < */
    SPC_INC   = 2,  /* + */
    SPC_DEC   = 3,  /* - */
    SPC_OUT   = 4,  /* . */
    SPC_IN    = 5,  /* , */
    SPC_LOOP_START = 6, /* [ */
    SPC_LOOP_END  = 7, /* ] */
} spaces_cmd_t;

/* Mapping: 3-bit code -> Spaces command (internal code) */
spaces_cmd_t op_map[8] = {
    SPC_RIGHT, SPC_LEFT, SPC_INC, SPC_DEC,
    SPC_OUT,   SPC_IN,   SPC_LOOP_START, SPC_LOOP_END
};

void panic(const char *msg) {
    fprintf(stderr, "Spaces VM Error: %s\n", msg);
    exit(1);
}

/* UTF-8 full-width space detection with Bounds Checking */
int is_full_space(const unsigned char *s, int idx, int len) {
    if (idx + 2 >= len) return 0;
    if (s[idx] == 0xE3 && s[idx+1] == 0x80 && s[idx+2] == 0x80) {
        return 1;
    }
    return 0;
}

/* parse_line: convert line with spaces/full-width spaces into Spaces command stream */
int parse_line(const char *input, int input_len, spaces_cmd_t *output, int max_out) {
    int out_idx = 0;
    int bit_buf = 0;
    int bit_cnt = 0;
    for (int i = 0; i < input_len && input[i] != 0; i++) {
        int bit = -1;
        unsigned char uc = (unsigned char)input[i];
        if (uc == 0x20) {
            bit = 0;
        } else if (uc == 0xE3) {
            if (is_full_space((const unsigned char*)input, i, input_len)) {
                bit = 1;
                i += 2; /* skip the remaining bytes of full-width space */
            }
        }
        if (bit != -1) {
            bit_buf = (bit_buf << 1) | (bit & 1);
            bit_cnt++;
            if (bit_cnt == 3) {
                if (out_idx >= max_out - 1) panic("Output buffer overflow");
                output[out_idx++] = op_map[bit_buf & 0x7];
                bit_buf = 0;
                bit_cnt = 0;
            }
        }
    }
    return out_idx;
}

/* Spaces VM runner -- directly interprets Spaces commands */
void run_spaces(spaces_cmd_t *code, int code_len) {
    int pc = 0;
    memset(tape, 0, sizeof(tape));
    ptr = 0;

    /* Precompute loop pairs for efficiency */
    int *loop_map = malloc(code_len * sizeof(int));
    if (!loop_map) panic("Alloc fail for loop_map");
    int stack[code_len]; /* rough upper bound */
    int sp = 0;
    for (int i = 0; i < code_len; i++) {
        if (code[i] == SPC_LOOP_START) {
            stack[sp++] = i;
        } else if (code[i] == SPC_LOOP_END) {
            if (sp == 0) panic("Unmatched SPC_LOOP_END");
            int start = stack[--sp];
            loop_map[start] = i;
            loop_map[i] = start;
        }
    }
    if (sp != 0) panic("Unmatched SPC_LOOP_START");

    while (pc < code_len) {
        switch (code[pc]) {
            case SPC_RIGHT:
                ptr++;
                if (ptr >= TAPE_SIZE) panic("Tape pointer overflow (Right)");
                break;
            case SPC_LEFT:
                ptr--;
                if (ptr < 0) panic("Tape pointer underflow (Left)");
                break;
            case SPC_INC:
                tape[ptr]++;
                break;
            case SPC_DEC:
                tape[ptr]--;
                break;
            case SPC_OUT:
                putchar(tape[ptr]);
                break;
            case SPC_IN:
                {
                    int c = getchar();
                    tape[ptr] = (c == EOF) ? 0 : (unsigned char)c;
                }
                break;
            case SPC_LOOP_START:
                if (tape[ptr] == 0) {
                    pc = loop_map[pc];
                }
                break;
            case SPC_LOOP_END:
                if (tape[ptr] != 0) {
                    pc = loop_map[pc];
                }
                break;
            default:
                /* ignore invalid codes (should not happen) */
                break;
        }
        pc++;
    }
    free(loop_map);
}

/* Helper: process an in-memory buffer that may be SPA header or spaces-encoded */
void process_buffer(unsigned char *in, size_t n) {
    /* allocate command buffer */
    size_t cmd_cap = n + 128;
    if (cmd_cap < 4096) cmd_cap = 4096;
    spaces_cmd_t *cmd = malloc(cmd_cap * sizeof(spaces_cmd_t));
    if (!cmd) panic("Alloc fail");

    if (n >= 3 && in[0] == 'S' && in[1] == 'P' && in[2] == 'A') {
        /* SPA binary format: map 1..8 -> Spaces commands */
        size_t out_idx = 0;
        for (long i = 3; i < (long)n; i++) {
            unsigned char op = in[i];
            if (op >= 1 && op <= 8) {
                cmd[out_idx++] = op_map[op - 1];
            }
            if (out_idx + 16 >= cmd_cap) {
                cmd_cap *= 2;
                spaces_cmd_t *tmp = realloc(cmd, cmd_cap * sizeof(spaces_cmd_t));
                if (!tmp) { free(cmd); panic("Alloc fail"); }
                cmd = tmp;
            }
        }
        /* Execute the Spaces program */
        run_spaces(cmd, (int)out_idx);
    } else {
        /* spaces-encoded Spaces: parse whole input into command stream and run it */
        int parsed = parse_line((const char*)in, (int)n, cmd, (int)cmd_cap);
        if (parsed > 0) {
            run_spaces(cmd, parsed);
        }
    }
    free(cmd);
}

int main(int argc, char **argv) {
    /* Windows: force stdout binary if needed */
#ifdef _WIN32
    _setmode(_fileno(stdout), _O_BINARY);
#endif

    if (argc > 1) {
        /* file provided as argument: read whole file and execute it as Spaces program */
        FILE *f = fopen(argv[1], "rb");
        if (!f) { perror("File open error"); return 1; }
        if (fseek(f, 0, SEEK_END) != 0) { fclose(f); panic("fseek failed"); }
        long s = ftell(f);
        if (s < 0 || s > MAX_FILE_SIZE) { fclose(f); fprintf(stderr, "File too large\n"); return 1; }
        if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); panic("fseek failed"); }
        unsigned char *in = malloc((size_t)s + 1);
        if (!in) { fclose(f); panic("Alloc fail"); }
        size_t n = fread(in, 1, (size_t)s, f);
        fclose(f);
        in[n] = 0;
        process_buffer(in, n);
        free(in);
        return 0;
    }

    /* No argv: decide interactive REPL vs non-interactive (piped) stdin */
    if (!isatty(fileno(stdin))) {
        /* Non-interactive: read all stdin into buffer and process once */
        size_t cap = 8192;
        size_t n = 0;
        unsigned char *in = malloc(cap + 1);
        if (!in) panic("Alloc fail");
        while (1) {
            size_t toread = cap - n;
            if (toread == 0) {
                cap *= 2;
                unsigned char *tmp = realloc(in, cap + 1);
                if (!tmp) { free(in); panic("Alloc fail"); }
                in = tmp;
                toread = cap - n;
            }
            size_t r = fread(in + n, 1, toread, stdin);
            if (r == 0) break;
            n += r;
            if (n > MAX_FILE_SIZE) { free(in); panic("Input too large"); }
        }
        in[n] = 0;
        process_buffer(in, n);
        free(in);
        return 0;
    }

    /* TTY interactive REPL */
    fprintf(stderr, "Spaces REPL (Spaces VM)\n");
    char line[4096];
    spaces_cmd_t cmd_buf[4096];
    while (1) {
        if (!fgets(line, sizeof(line), stdin)) break;
        int parsed = parse_line(line, (int)strlen(line), cmd_buf, (int)(sizeof(cmd_buf)/sizeof(cmd_buf[0])));
        if (parsed > 0) {
            run_spaces(cmd_buf, parsed);
            printf("\n");
        }
    }
    return 0;
}