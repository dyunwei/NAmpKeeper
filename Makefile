# path macros
BIN_PATH := bin
OBJ_PATH := obj
SRC_PATH := src
INC_PATH := include

# compile macros
TARGET_NAME := daam
TARGET := $(BIN_PATH)/$(TARGET_NAME)
MACRO =

# tool macros
CXX := g++ -g -ggdb3 -Wall -std=c++11 
CXXFLAGS := 
CCOBJFLAGS := $(CXXFLAGS) -I $(INC_PATH) -c $(MACRO)
LDFLAGS := -lm

# src files & obj files
SRCS := $(foreach x, $(SRC_PATH), $(wildcard $(addprefix $(x)/*,.c*)))
INCS := $(foreach x, $(INC_PATH), $(wildcard $(addprefix $(x)/*,.h*)))
OBJS := $(addprefix $(OBJ_PATH)/, $(addsuffix .o, $(notdir $(basename $(SRCS)))))

#$(info info: $(SRCS))

# clean files list
CLEAN_LIST := $(TARGET) \
				$(OBJS)

# default rule
default: makedir all

# non-phony targets
$(OBJ_PATH)/%.o: $(SRC_PATH)/%.c* $(INC_PATH)/*.h*
	$(CXX) $(CCOBJFLAGS) -o $@ $<

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $(OBJS)

# phony rules
.PHONY: makedir
makedir:
	@mkdir -p $(BIN_PATH) $(OBJ_PATH)

.PHONY: all
all: $(TARGET)

.PHONY: clean
clean:
	@echo CLEAN $(CLEAN_LIST)
	@rm -f $(CLEAN_LIST)

.PHONY: clean_all
clean_all:
	@echo CLEAN $(BIN_PATH) $(OBJ_PATH) 
	@rm -rf $(BIN_PATH) $(OBJ_PATH) 
