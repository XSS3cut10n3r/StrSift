/*
 * StrSift - Interactive strings search tool for file analysis
 *
 * Features:
 * - Extract strings from binary files
 * - Multiple encoding support (ASCII, UTF-16LE, UTF-16BE)
 * - Regex search capabilities
 * - Context display around matches
 * - Auto-categorization (URLs, IPs, paths)
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <regex.h>
#include <getopt.h>
#include <stdint.h>
#include <stdbool.h>

#define VERSION "1.0.0"
#define DEFAULT_MIN_LENGTH 4
#define MAX_STRING_LENGTH 4096
#define CONTEXT_BYTES 32

/* String encoding types */
typedef enum {
    ENCODING_ASCII,
    ENCODING_UTF16LE,
    ENCODING_UTF16BE,
    ENCODING_ALL
} encoding_t;

/* String category types */
typedef enum {
    CAT_NONE,
    CAT_URL,
    CAT_IP,
    CAT_PATH,
    CAT_EMAIL
} category_t;

/* Configuration structure */
typedef struct {
    char *filename;
    char *regex_pattern;
    int min_length;
    encoding_t encoding;
    bool show_offset;
    bool show_context;
    bool categorize;
    bool interactive;
    size_t context_bytes;
} config_t;

/* Extracted string structure */
typedef struct {
    char *data;
    size_t offset;
    size_t length;
    encoding_t encoding;
    category_t category;
} extracted_string_t;

/* Dynamic array for strings */
typedef struct {
    extracted_string_t *strings;
    size_t count;
    size_t capacity;
} string_array_t;

/* Function prototypes */
void print_usage(const char *progname);
void print_version(void);
void init_string_array(string_array_t *arr);
void add_string(string_array_t *arr, const char *str, size_t offset, size_t len, encoding_t enc);
void free_string_array(string_array_t *arr);
category_t categorize_string(const char *str);
const char *category_name(category_t cat);
const char *encoding_name(encoding_t enc);
void extract_strings(FILE *fp, config_t *cfg, string_array_t *arr);
void extract_ascii_strings(FILE *fp, config_t *cfg, string_array_t *arr);
void extract_utf16_strings(FILE *fp, config_t *cfg, string_array_t *arr, bool little_endian);
void filter_and_display(string_array_t *arr, config_t *cfg);
void display_string(extracted_string_t *str, config_t *cfg, FILE *fp);
void show_context(FILE *fp, size_t offset, size_t length, size_t context_bytes);

/* Print usage information */
void print_usage(const char *progname) {
    printf("StrSift v%s - Interactive strings search tool for file analysis\n\n", VERSION);
    printf("Usage: %s [OPTIONS] FILE\n\n", progname);
    printf("OPTIONS:\n");
    printf("  -e, --encoding TYPE    Encoding type: ascii, utf16le, utf16be, all (default: all)\n");
    printf("  -n, --min-length NUM   Minimum string length (default: %d)\n", DEFAULT_MIN_LENGTH);
    printf("  -r, --regex PATTERN    Filter strings by regex pattern\n");
    printf("  -o, --offset           Show file offset for each string\n");
    printf("  -c, --context          Show context bytes around strings\n");
    printf("  -C, --context-bytes N  Number of context bytes (default: %d)\n", CONTEXT_BYTES);
    printf("  -a, --categorize       Auto-categorize strings (URLs, IPs, paths, emails)\n");
    printf("  -i, --interactive      Interactive mode (coming soon)\n");
    printf("  -h, --help             Display this help message\n");
    printf("  -v, --version          Display version information\n\n");
    printf("EXAMPLES:\n");
    printf("  %s binary_file                    # Extract all strings\n", progname);
    printf("  %s -n 8 -o binary_file            # Min length 8, show offsets\n", progname);
    printf("  %s -r \"http.*\" -a binary_file     # Find URLs\n", progname);
    printf("  %s -e utf16le binary_file         # Extract UTF-16LE strings only\n", progname);
    printf("  %s -c -C 16 binary_file           # Show 16 bytes of context\n", progname);
}

/* Print version information */
void print_version(void) {
    printf("StrSift v%s\n", VERSION);
    printf("Interactive strings search tool for file analysis\n");
}

/* Initialize string array */
void init_string_array(string_array_t *arr) {
    arr->count = 0;
    arr->capacity = 1024;
    arr->strings = malloc(arr->capacity * sizeof(extracted_string_t));
    if (!arr->strings) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        exit(1);
    }
}

/* Add string to array */
void add_string(string_array_t *arr, const char *str, size_t offset, size_t len, encoding_t enc) {
    if (arr->count >= arr->capacity) {
        arr->capacity *= 2;
        arr->strings = realloc(arr->strings, arr->capacity * sizeof(extracted_string_t));
        if (!arr->strings) {
            fprintf(stderr, "Error: Memory reallocation failed\n");
            exit(1);
        }
    }

    extracted_string_t *s = &arr->strings[arr->count];
    s->data = strdup(str);
    s->offset = offset;
    s->length = len;
    s->encoding = enc;
    s->category = CAT_NONE;

    if (!s->data) {
        fprintf(stderr, "Error: String duplication failed\n");
        exit(1);
    }

    arr->count++;
}

/* Free string array */
void free_string_array(string_array_t *arr) {
    for (size_t i = 0; i < arr->count; i++) {
        free(arr->strings[i].data);
    }
    free(arr->strings);
}

/* Categorize string based on patterns */
category_t categorize_string(const char *str) {
    /* URL detection */
    if (strstr(str, "http://") || strstr(str, "https://") ||
        strstr(str, "ftp://") || strstr(str, "file://")) {
        return CAT_URL;
    }

    /* Email detection (simple pattern) */
    const char *at = strchr(str, '@');
    if (at && strchr(at, '.')) {
        return CAT_EMAIL;
    }

    /* IP address detection (simple check) */
    int dots = 0, digits = 0;
    for (const char *p = str; *p; p++) {
        if (*p == '.') dots++;
        else if (isdigit(*p)) digits++;
        else if (*p != ':' && !isxdigit(*p)) break;
    }
    if (dots == 3 && digits >= 4) {
        return CAT_IP;
    }

    /* Path detection (Unix and Windows) */
    if (str[0] == '/' || (strlen(str) > 2 && str[1] == ':' && (str[2] == '\\' || str[2] == '/'))) {
        return CAT_PATH;
    }
    if (strstr(str, "\\\\") || strstr(str, "/bin/") || strstr(str, "/usr/") ||
        strstr(str, "/etc/") || strstr(str, "C:\\") || strstr(str, "\\Windows\\")) {
        return CAT_PATH;
    }

    return CAT_NONE;
}

/* Get category name */
const char *category_name(category_t cat) {
    switch (cat) {
        case CAT_URL: return "URL";
        case CAT_IP: return "IP";
        case CAT_PATH: return "PATH";
        case CAT_EMAIL: return "EMAIL";
        default: return "NONE";
    }
}

/* Get encoding name */
const char *encoding_name(encoding_t enc) {
    switch (enc) {
        case ENCODING_ASCII: return "ASCII";
        case ENCODING_UTF16LE: return "UTF16LE";
        case ENCODING_UTF16BE: return "UTF16BE";
        default: return "UNKNOWN";
    }
}

/* Extract ASCII strings */
void extract_ascii_strings(FILE *fp, config_t *cfg, string_array_t *arr) {
    char buffer[MAX_STRING_LENGTH];
    int buf_pos = 0;
    size_t offset = 0;
    size_t string_start = 0;
    int c;

    fseek(fp, 0, SEEK_SET);

    while ((c = fgetc(fp)) != EOF) {
        if (isprint(c) || c == '\t' || c == '\r' || c == '\n') {
            if (buf_pos == 0) {
                string_start = offset;
            }

            if (buf_pos < MAX_STRING_LENGTH - 1) {
                buffer[buf_pos++] = c;
            }
        } else {
            if (buf_pos >= cfg->min_length) {
                buffer[buf_pos] = '\0';
                add_string(arr, buffer, string_start, buf_pos, ENCODING_ASCII);
            }
            buf_pos = 0;
        }
        offset++;
    }

    /* Handle last string if file doesn't end with non-printable */
    if (buf_pos >= cfg->min_length) {
        buffer[buf_pos] = '\0';
        add_string(arr, buffer, string_start, buf_pos, ENCODING_ASCII);
    }
}

/* Extract UTF-16 strings */
void extract_utf16_strings(FILE *fp, config_t *cfg, string_array_t *arr, bool little_endian) {
    char buffer[MAX_STRING_LENGTH];
    int buf_pos = 0;
    size_t offset = 0;
    size_t string_start = 0;
    uint8_t b1, b2;

    fseek(fp, 0, SEEK_SET);

    while (fread(&b1, 1, 1, fp) == 1 && fread(&b2, 1, 1, fp) == 1) {
        uint16_t c = little_endian ? (b2 << 8 | b1) : (b1 << 8 | b2);

        /* Only handle ASCII-range characters in UTF-16 */
        if (c > 0 && c < 128 && (isprint(c) || c == '\t' || c == '\r' || c == '\n')) {
            if (buf_pos == 0) {
                string_start = offset;
            }

            if (buf_pos < MAX_STRING_LENGTH - 1) {
                buffer[buf_pos++] = (char)c;
            }
        } else {
            if (buf_pos >= cfg->min_length) {
                buffer[buf_pos] = '\0';
                add_string(arr, buffer, string_start, buf_pos,
                          little_endian ? ENCODING_UTF16LE : ENCODING_UTF16BE);
            }
            buf_pos = 0;
        }
        offset += 2;
    }

    /* Handle last string */
    if (buf_pos >= cfg->min_length) {
        buffer[buf_pos] = '\0';
        add_string(arr, buffer, string_start, buf_pos,
                  little_endian ? ENCODING_UTF16LE : ENCODING_UTF16BE);
    }
}

/* Extract all strings based on configuration */
void extract_strings(FILE *fp, config_t *cfg, string_array_t *arr) {
    if (cfg->encoding == ENCODING_ASCII || cfg->encoding == ENCODING_ALL) {
        extract_ascii_strings(fp, cfg, arr);
    }

    if (cfg->encoding == ENCODING_UTF16LE || cfg->encoding == ENCODING_ALL) {
        extract_utf16_strings(fp, cfg, arr, true);
    }

    if (cfg->encoding == ENCODING_UTF16BE || cfg->encoding == ENCODING_ALL) {
        extract_utf16_strings(fp, cfg, arr, false);
    }
}

/* Show context bytes around a string */
void show_context(FILE *fp, size_t offset, size_t length, size_t context_bytes) {
    size_t start = (offset > context_bytes) ? (offset - context_bytes) : 0;
    size_t end = offset + length + context_bytes;

    fseek(fp, start, SEEK_SET);

    printf("    Context [0x%lx - 0x%lx]:\n    ", start, end);

    for (size_t i = start; i < end; i++) {
        int c = fgetc(fp);
        if (c == EOF) break;

        /* Highlight the actual string */
        if (i == offset) printf("\033[1;32m"); /* Green bold */

        if (isprint(c)) {
            printf("%c", c);
        } else {
            printf("\\x%02x", (unsigned char)c);
        }

        if (i == offset + length - 1) printf("\033[0m"); /* Reset */
    }
    printf("\n");
}

/* Display a single string */
void display_string(extracted_string_t *str, config_t *cfg, FILE *fp) {
    /* Show offset if requested */
    if (cfg->show_offset) {
        printf("[0x%08lx] ", str->offset);
    }

    /* Show encoding */
    printf("<%s> ", encoding_name(str->encoding));

    /* Show category if enabled */
    if (cfg->categorize && str->category != CAT_NONE) {
        printf("[%s] ", category_name(str->category));
    }

    /* Show the string */
    printf("%s\n", str->data);

    /* Show context if requested */
    if (cfg->show_context && fp) {
        show_context(fp, str->offset, str->length, cfg->context_bytes);
    }
}

/* Filter and display strings */
void filter_and_display(string_array_t *arr, config_t *cfg) {
    regex_t regex;
    bool use_regex = (cfg->regex_pattern != NULL);
    FILE *fp = NULL;

    /* Compile regex if provided */
    if (use_regex) {
        int ret = regcomp(&regex, cfg->regex_pattern, REG_EXTENDED | REG_NOSUB);
        if (ret != 0) {
            char error_buf[256];
            regerror(ret, &regex, error_buf, sizeof(error_buf));
            fprintf(stderr, "Error: Invalid regex pattern: %s\n", error_buf);
            return;
        }
    }

    /* Open file for context display if needed */
    if (cfg->show_context) {
        fp = fopen(cfg->filename, "rb");
        if (!fp) {
            fprintf(stderr, "Warning: Cannot open file for context display\n");
        }
    }

    /* Categorize strings if requested */
    if (cfg->categorize) {
        for (size_t i = 0; i < arr->count; i++) {
            arr->strings[i].category = categorize_string(arr->strings[i].data);
        }
    }

    /* Display strings */
    size_t displayed = 0;
    for (size_t i = 0; i < arr->count; i++) {
        extracted_string_t *str = &arr->strings[i];

        /* Apply regex filter if provided */
        if (use_regex) {
            if (regexec(&regex, str->data, 0, NULL, 0) != 0) {
                continue;
            }
        }

        display_string(str, cfg, fp);
        displayed++;
    }

    /* Cleanup */
    if (use_regex) {
        regfree(&regex);
    }

    if (fp) {
        fclose(fp);
    }

    /* Print summary */
    fprintf(stderr, "\nTotal strings extracted: %zu\n", arr->count);
    if (use_regex) {
        fprintf(stderr, "Strings matching pattern: %zu\n", displayed);
    }
}

/* Main function */
int main(int argc, char *argv[]) {
    config_t cfg = {
        .filename = NULL,
        .regex_pattern = NULL,
        .min_length = DEFAULT_MIN_LENGTH,
        .encoding = ENCODING_ALL,
        .show_offset = false,
        .show_context = false,
        .categorize = false,
        .interactive = false,
        .context_bytes = CONTEXT_BYTES
    };

    /* Long options */
    static struct option long_options[] = {
        {"encoding",      required_argument, 0, 'e'},
        {"min-length",    required_argument, 0, 'n'},
        {"regex",         required_argument, 0, 'r'},
        {"offset",        no_argument,       0, 'o'},
        {"context",       no_argument,       0, 'c'},
        {"context-bytes", required_argument, 0, 'C'},
        {"categorize",    no_argument,       0, 'a'},
        {"interactive",   no_argument,       0, 'i'},
        {"help",          no_argument,       0, 'h'},
        {"version",       no_argument,       0, 'v'},
        {0, 0, 0, 0}
    };

    /* Parse command line options */
    int opt;
    while ((opt = getopt_long(argc, argv, "e:n:r:ocC:aihv", long_options, NULL)) != -1) {
        switch (opt) {
            case 'e':
                if (strcmp(optarg, "ascii") == 0) {
                    cfg.encoding = ENCODING_ASCII;
                } else if (strcmp(optarg, "utf16le") == 0) {
                    cfg.encoding = ENCODING_UTF16LE;
                } else if (strcmp(optarg, "utf16be") == 0) {
                    cfg.encoding = ENCODING_UTF16BE;
                } else if (strcmp(optarg, "all") == 0) {
                    cfg.encoding = ENCODING_ALL;
                } else {
                    fprintf(stderr, "Error: Invalid encoding type\n");
                    return 1;
                }
                break;
            case 'n':
                cfg.min_length = atoi(optarg);
                if (cfg.min_length < 1) {
                    fprintf(stderr, "Error: Minimum length must be at least 1\n");
                    return 1;
                }
                break;
            case 'r':
                cfg.regex_pattern = optarg;
                break;
            case 'o':
                cfg.show_offset = true;
                break;
            case 'c':
                cfg.show_context = true;
                break;
            case 'C':
                cfg.context_bytes = atoi(optarg);
                if (cfg.context_bytes < 1) {
                    fprintf(stderr, "Error: Context bytes must be at least 1\n");
                    return 1;
                }
                break;
            case 'a':
                cfg.categorize = true;
                break;
            case 'i':
                cfg.interactive = true;
                fprintf(stderr, "Note: Interactive mode not yet implemented\n");
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            case 'v':
                print_version();
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    /* Check for filename argument */
    if (optind >= argc) {
        fprintf(stderr, "Error: No input file specified\n\n");
        print_usage(argv[0]);
        return 1;
    }

    cfg.filename = argv[optind];

    /* Open input file */
    FILE *fp = fopen(cfg.filename, "rb");
    if (!fp) {
        perror("Error opening file");
        return 1;
    }

    /* Initialize string array */
    string_array_t strings;
    init_string_array(&strings);

    /* Extract strings */
    fprintf(stderr, "Extracting strings from '%s'...\n", cfg.filename);
    extract_strings(fp, &cfg, &strings);
    fclose(fp);

    /* Filter and display results */
    filter_and_display(&strings, &cfg);

    /* Cleanup */
    free_string_array(&strings);

    return 0;
}
