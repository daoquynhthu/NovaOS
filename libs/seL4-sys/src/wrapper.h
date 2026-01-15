/* wrapper.h: Entry point for bindgen */

/* 
 * 强制定义一些 bindgen 可能遗漏的宏，或者为 bindgen 简化复杂的 C 语法 
 */
#define __BINDGEN__

/* 包含 seL4 的主头文件 */
#include <sel4/sel4.h>
