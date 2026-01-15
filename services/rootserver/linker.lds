ENTRY(_start)

SECTIONS
{
    /* Load RootServer at 32MB to avoid conflict with Kernel (at 1MB-10MB) */
    . = 0x2000000;

    .text : {
        KEEP(*(.text.start))
        *(.text .text.*)
    }

    .rodata : {
        *(.rodata .rodata.*)
    }

    .data : {
        *(.data .data.*)
    }

    .bss : {
        *(.bss .bss.*)
        *(COMMON)
    }
    
    /DISCARD/ : {
        *(.eh_frame)
        *(.comment)
    }
}
