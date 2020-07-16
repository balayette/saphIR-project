# saphIR project

saphIR is an Intermediate Representation with amd64 and aarch64 backends.
This project contains both the IR code, and projects that use it.

## Subprojects

See the subdirectories for more detailed descriptions.

* `saphIR/`: The IR itself
* `compiler/`: A compiler frontend that targets `saphIR`

## Building
```
mkdir build && cd build
cmake ..
make
```
