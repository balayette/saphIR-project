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
      src/frontend/stmt.o \
      src/frontend/exp.o \
      src/frontend/sema/sema.o \
      src/frontend/sema/tycheck.o \
      src/frontend/visitors/pretty-printer.o \
      src/frontend/visitors/transforms.o \
      src/frontend/visitors/translate.o \
      src/frontend/visitors/default-visitor.o \
      src/mach/amd64/amd64-access.o \
      src/mach/amd64/amd64-target.o \
      src/mach/amd64/amd64-common.o \
      src/mach/amd64/amd64-codegen.o \
      src/mach/amd64/amd64-instr.o \
      src/mach/aarch64/aarch64-instr.o \
      src/mach/aarch64/aarch64-target.o \
      src/mach/aarch64/aarch64-common.o \
      src/mach/aarch64/aarch64-access.o \
      src/mach/aarch64/aarch64-codegen.o \
      src/mach/access.o \
      src/mach/target.o \
      src/ir/ir.o \
      src/ir/types.o \
      src/ir/canon/linearize.o \
      src/ir/canon/bb.o \
      src/ir/canon/trace.o \
      src/ir/visitors/default-ir-visitor.o \
      src/ir/visitors/ir-pretty-printer.o \
      src/ir/visitors/ir-cloner-visitor.o \
      src/ir/visitors/ir-binop-optimizer.o \
      src/ir/visitors/ir-arith-optimizer.o \
      src/ir/visitors/ir-cnst-obfuscator.o \
      src/ass/instr.o \
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
