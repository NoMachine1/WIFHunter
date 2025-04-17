# Compiler settings
CXX         := g++  # or clang++ on Linux
CXXFLAGS    := -m64 -std=c++17 -mssse3 -msse4.1 -Ofast -Wall -Wextra  \
           -funroll-loops -ftree-vectorize -fstrict-aliasing  \
           -fno-semantic-interposition -fno-exceptions -fno-rtti -flto -pthread -mavx2 -mbmi2 -madx

LDFLAGS     := -mavx2 -mbmi2 -madx -pthread

# Platform-specific settings
ifeq ($(OS),Windows_NT)
    EXE     := WIFHunter.exe
    LDFLAGS += -static
else
    EXE     := WIFHunter
    CXXFLAGS += -fPIC
endif

# Source files
SRCS        := WIFHunter.cpp sha256_avx2.cpp 
OBJS        := $(SRCS:.cpp=.o)
DEPS        := $(SRCS:.cpp=.d)

# Targets
all: $(EXE)
	@$(MAKE) clean_intermediates

$(EXE): $(OBJS)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -MMD -MP -c $< -o $@

# Include dependencies
-include $(DEPS)

# Clean intermediate files only (keep executable)
clean_intermediates:
	rm -f $(OBJS) $(DEPS)

# Clean everything (executable and intermediates)
clean: clean_intermediates
	rm -f $(EXE)

.PHONY: all clean clean_intermediates