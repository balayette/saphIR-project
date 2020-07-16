find_package(BISON REQUIRED)
find_package(FLEX REQUIRED)

BISON_TARGET(compiler_parser
        src/frontend/parser/parser.yy
        ${CMAKE_CURRENT_BINARY_DIR}/parser.cc
        COMPILE_FLAGS "-v -t"
        DEFINES_FILE ${CMAKE_CURRENT_BINARY_DIR}/parser.hh
)

FLEX_TARGET(compiler_lexer
        src/frontend/parser/scanner.ll
        ${CMAKE_CURRENT_BINARY_DIR}/scanner.cc
)

ADD_FLEX_BISON_DEPENDENCY(compiler_lexer compiler_parser)

add_executable(compiler
        ${FLEX_compiler_lexer_OUTPUTS}
        ${BISON_compiler_parser_OUTPUTS}
        src/main.cc
        src/driver/driver.cc
        src/frontend/stmt.cc
        src/frontend/exp.cc
        src/frontend/sema/sema.cc
        src/frontend/sema/tycheck.cc
        src/frontend/visitors/pretty-printer.cc
        src/frontend/visitors/transforms.cc
        src/frontend/visitors/translate.cc
        src/frontend/visitors/default-visitor.cc
)

target_include_directories(compiler
        PUBLIC
                ${CMAKE_CURRENT_SOURCE_DIR}/include
        PRIVATE
                ${CMAKE_CURRENT_BINARY_DIR}
)

target_link_libraries(compiler
        PUBLIC utils
        PUBLIC IR
)
