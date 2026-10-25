/* Verification address, not a recovered free camera region. Never insert this
 * ELF into the update. A future adapter must supply a verified placement plan. */
ENTRY(s3300_look_row)
SECTIONS
{
    . = 0x10000;
    .text : { *(.text*) } =0x00000000
    .rodata : { *(.rodata*) }
    .data : { *(.data*) }
    .bss : { *(.bss*) }
    /DISCARD/ : { *(.pdr) *(.comment) *(.note*) }
}
