# saphIR project

saphIR is an Intermediate Representation with amd64 and aarch64 backends.
This project contains both the IR code, and projects that use it.

## Subprojects

See the subdirectories for more detailed descriptions.

* `saphIR/`: The IR itself
* `compiler/`: A compiler frontend that targets `saphIR`
* `lifter/`: An ARM64 to saphIR lifter
* `dyn/`: A dynamic binary translator

## Building
```
mkdir build && cd build
cmake .. # -D CMAKE_BUILD_TYPE=Debug or -D CMAKE_BUILD_TYPE=Release
make
```
