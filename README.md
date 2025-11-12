# StrSift

String extraction and analysis tool for binary files.

## Overview

StrSift extracts printable strings from binary files with support for multiple character encodings, pattern matching, and automatic categorization. It provides enhanced functionality over traditional string extraction tools with regex filtering, offset tracking, and context display capabilities.

## Features

- Multiple encoding support: ASCII, UTF-16LE, UTF-16BE
- Regular expression pattern filtering
- File offset display for extracted strings
- Context byte display around matches
- Automatic categorization of URLs, IP addresses, file paths, and email addresses
- Configurable minimum string length
- Optimized C implementation for performance

## Installation

### Requirements

- C compiler (GCC, Clang)
- POSIX-compliant system (Linux, macOS, BSD)
- Standard C library with regex support

### Building

```bash
git clone https://github.com/XSS3cut01n3r/strsift.git
cd strsift
gcc -o strsift strsift.c -O2
sudo cp strsift /usr/local/bin/  # optional
```

## Usage

```
strsift [OPTIONS] FILE
```

### Basic Examples

Extract all strings:
```bash
strsift binary_file
```

Find URLs:
```bash
strsift -r "http.*" -a malware.exe
```

Show offsets and context:
```bash
strsift -o -c firmware.bin
```

### Command Line Options

| Option | Long Form | Description |
|--------|-----------|-------------|
| `-e TYPE` | `--encoding TYPE` | Encoding type: `ascii`, `utf16le`, `utf16be`, `all` (default: all) |
| `-n NUM` | `--min-length NUM` | Minimum string length (default: 4) |
| `-r PATTERN` | `--regex PATTERN` | Filter strings by regex pattern |
| `-o` | `--offset` | Show file offset for each string |
| `-c` | `--context` | Show context bytes around strings |
| `-C N` | `--context-bytes N` | Number of context bytes (default: 32) |
| `-a` | `--categorize` | Auto-categorize strings (URLs, IPs, paths, emails) |
| `-i` | `--interactive` | Interactive mode (coming soon) |
| `-h` | `--help` | Display help message |
| `-v` | `--version` | Display version information |

## Detailed Examples

### String Extraction with Minimum Length
```bash
strsift -n 8 program.exe
```

Output:
```
<ASCII> Microsoft Corporation
<ASCII> Windows NT
<UTF16LE> Application Error
```

### Pattern Matching
```bash
strsift -r "http|@" -a suspicious.dll
```

Output:
```
<ASCII> [URL] https://example.com/payload
<ASCII> [EMAIL] attacker@evil.com
```

### Offset and Context Display
```bash
strsift -o -c -C 16 firmware.bin
```

Output:
```
[0x00001a40] <ASCII> /etc/passwd
    Context [0x00001a30 - 0x00001a60]:
    \x00\x00\x00\x00/etc/passwd\x00\x00\x00\x00
```

### Encoding-Specific Extraction
```bash
strsift -e utf16le -n 6 windows_binary.exe
```

### Path Extraction
```bash
strsift -r "^(/|[A-Z]:)" -a executable
```

Output:
```
<ASCII> [PATH] C:\Windows\System32\kernel32.dll
<ASCII> [PATH] /usr/lib/libc.so.6
```

### IP Address Extraction

```bash
strsift -r "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" -a network_dump
```

## Use Cases

- Malware analysis: Extract suspicious strings, URLs, and IP addresses from samples
- Firmware analysis: Discover hardcoded credentials and configuration data
- Reverse engineering: Locate function names, error messages, and embedded resources
- Digital forensics: Recover text from binary files
- Security research: Identify potential vulnerabilities and indicators of compromise
- Data recovery: Extract readable text from corrupted files

## Technical Details

### Supported Encodings

- **ASCII** - 7-bit ASCII characters (printable + whitespace)
- **UTF-16LE** - Little-endian UTF-16 (Windows default)
- **UTF-16BE** - Big-endian UTF-16 (network byte order)

### String Categorization

StrSift can automatically categorize extracted strings:

- **URLs** - `http://`, `https://`, `ftp://`, `file://`
- **Email Addresses** - Pattern: `user@domain.tld`
- **IP Addresses** - IPv4 addresses (e.g., `192.168.1.1`)
- **File Paths** - Unix (`/path/to/file`) and Windows (`C:\path\to\file`)

### Performance

- Typical throughput: ~100 MB/s on modern hardware
- Memory usage: O(n) where n is the number of extracted strings
- Supports files of arbitrary size

## Contributing

Contributions are welcome. Please submit pull requests or open issues for bugs and feature requests.

### Roadmap

- Interactive mode with TUI interface
- JSON output format
- Extended Unicode support
- String deduplication
- Multi-threaded processing
- Plugin system for custom categorizers

## License

MIT License - see LICENSE file for details.

## Author

For issues and questions, please use the GitHub issue tracker.
