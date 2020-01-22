CXXFLAGS = -Wall -Wextra -Werror -std=c++17 -pedantic -g -MMD -Og
CPPFLAGS = -Iinclude/
LINK.o = $(LINK.cc)

PARSER = frontend/parser

GENERATED = \
		src/$(PARSER)/parser.cc \
		src/$(PARSER)/scanner.cc \

TRASH_HDR = \
	    src/$(PARSER)/parser.hh \
	    src/$(PARSER)/location.hh \
	    include/$(PARSER)/parser.hh \
	    include/$(PARSER)/location.hh \

GENERATED_OBJ = $(GENERATED:.cc=.o)

OBJ = \
      $(GENERATED_OBJ) \
      src/frontend/parser/scanner.o \
      src/frontend/parser/parser.o \
      src/main.o \
      src/utils/symbol.o \
      src/utils/assert.o \
      src/driver/driver.o \
      src/frontend/types.o \
      src/frontend/stmt.o \
      src/frontend/sema/sema.o \
      src/frontend/sema/tycheck.o \
      src/frontend/visitors/pretty-printer.o \
      src/frontend/visitors/transforms.o \
      src/frontend/visitors/translate.o \
      src/frontend/visitors/default-visitor.o \
      src/mach/frame.o \
      src/ir/canon/linearize.o \
      src/ir/canon/bb.o \
      src/ir/canon/trace.o \
      src/ir/visitors/default-ir-visitor.o \
      src/ir/visitors/ir-pretty-printer.o \
      src/ir/opt/peephole.o \
      src/ass/instr.o \
      src/mach/codegen.o \
      src/backend/cfg.o \
      src/backend/liveness.o \
      src/backend/regalloc.o \
      src/backend/color.o \
      src/frontend/ops.o \

DEP = $(OBJ:.o=.d)

BIN_OUT = jit

$(BIN_OUT): src/main
	cp $^ $@

src/main: $(OBJ)

src/main.o: $(GENERATED)

$(OBJ): src/frontend/parser/parser.cc
src/frontend/parser/parser.cc: src/frontend/parser/parser.yy
	bison -v -t src/frontend/parser/parser.yy -o \
		src/frontend/parser/parser.cc \
		--defines=include/frontend/parser/parser.hh
	cp src/$(PARSER)/location.hh include/$(PARSER)/location.hh
	cp include/$(PARSER)/parser.hh src/$(PARSER)/parser.hh

src/frontend/parser/scanner.cc: src/$(PARSER)/parser.cc
	flex -f -o src/frontend/parser/scanner.cc src/frontend/parser/scanner.ll

clean:
	$(RM) $(OBJ) src/main $(BIN_OUT) $(DEP) $(GENERATED) $(TRASH_HDR)
	$(RM) src/$(PARSER)/parser.output

-include $(DEP)
