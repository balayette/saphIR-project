# Compiler

A frontend for a simple language, which targets saphIR

## Example

```
fun printf(string fmt) int variadic;

struct pair { int a, int b };

fun mult(pair* p) int {
        let int ret = 0;
        for (let int i = 1; i != p->b + 1; i = i + 1)
                ret = ret + p->a;
        rof
        return ret;
}

fun fact(int n) int {
        let int ret = 1;
        for (let int i = 1; i != n + 1; i = i + 1)
                let pair p = {ret, i};
                ret = mult(&p);
        rof
        return ret;
}

fun main(int a) int {
        for (let int i = 0; i != a; i = i + 1)
                printf("%d\n", fact(i));
        rof

        return a;
}
```

## Notable language features

* Structures, arrays, pointers
* Variable size integers
* Inline assembly
* Brace initialization of structures and arrays
