#pragma once

#define ROUND_UP(x, m) (((x) + (m)-1) & ~((m)-1))

#define IS_POWER_OF_TWO(x) (((x) & ((x)-1)) == 0)
