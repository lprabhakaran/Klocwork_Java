# Compiler and flags
CXX := g++
CXXFLAGS := -Wall -Wextra
LDFLAGS :=
LDLIBS :=

# Directories
SRC_DIR := project/src
BUILD_DIR := project/build

# Source files
SRCS := $(wildcard $(SRC_DIR)/*.cpp)

# Output binary
TARGET := $(BUILD_DIR)/hello

# Default target
all: $(TARGET)

# Ensure build directory exists before building
$(TARGET): $(SRCS) | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LDLIBS)

# Rule to create the build directory
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Clean target
clean:
	rm -f $(TARGET)

.PHONY: all clean
