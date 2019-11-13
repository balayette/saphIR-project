CXXFLAGS = -Wall -Wextra -std=c++17 -pedantic -g -MMD
LINK.o = $(LINK.cc)

OBJ = \
      src/lexer.o \
      src/parser.o \
      src/token.o \
      src/tree.o \
      src/main.o \

BIN_OUT = jit

$(BIN_OUT): src/main
	cp $^ $@

src/main: $(OBJ)

clean:
	$(RM) $(OBJ) src/main $(BIN_OUT)
