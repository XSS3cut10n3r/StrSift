# StrSift Makefile

# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c99
LDFLAGS =

# Target binary
TARGET = strsift

# Source files
SOURCES = strsift.c
OBJECTS = $(SOURCES:.c=.o)

# Default target
all: $(TARGET)

# Build the binary
$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJECTS) $(LDFLAGS)
	@echo ""
	@echo "Build complete! Run with: ./$(TARGET) --help"

# Compile source files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Install to /usr/local/bin (requires root)
install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/

# Uninstall from /usr/local/bin
uninstall:
	rm -f /usr/local/bin/$(TARGET)

# Clean build artifacts
clean:
	rm -f $(OBJECTS) $(TARGET)

# Run basic tests
test: $(TARGET)
	@echo "Running basic tests..."
	@echo "Test 1: Help output"
	./$(TARGET) --help
	@echo ""
	@echo "Test 2: Version output"
	./$(TARGET) --version
	@echo ""
	@echo "Test 3: Extract strings from Makefile itself"
	./$(TARGET) -n 3 -o Makefile | head -20

# Create a test binary for demonstration
test-binary:
	@echo "Creating test binary..."
	@echo -e "This is a test\x00\x00\x00URL: https://example.com\x00\x00" > test.bin
	@echo -e "Path: /usr/local/bin\x00IP: 192.168.1.1\x00" >> test.bin
	@echo -e "Email: test@example.com\x00" >> test.bin
	@echo "Test binary created: test.bin"

# Debug build
debug: CFLAGS += -g -DDEBUG
debug: clean $(TARGET)

.PHONY: all clean install uninstall test test-binary debug
