
import sys
import struct

def check_multiboot(filepath):
    try:
        with open(filepath, 'rb') as f:
            data = f.read(8192) # Read first 8KB
            
        # Multiboot 1 Magic: 0x1BADB002
        mb1_magic = b'\x02\xB0\xAD\x1B'
        mb1_offset = data.find(mb1_magic)
        
        # Multiboot 2 Magic: 0xE85250D6
        mb2_magic = b'\xD6\x50\x52\xE8'
        mb2_offset = data.find(mb2_magic)
        
        print(f"Checking {filepath}...")
        if mb1_offset != -1:
            print(f"Found Multiboot 1 Header at offset: {mb1_offset} (0x{mb1_offset:x})")
        else:
            print("Multiboot 1 Header NOT found in first 8KB")
            
        if mb2_offset != -1:
            print(f"Found Multiboot 2 Header at offset: {mb2_offset} (0x{mb2_offset:x})")
        else:
            print("Multiboot 2 Header NOT found in first 8KB")
            
        # Parse ELF Header (assuming 64-bit LE)
        if data[:4] == b'\x7fELF':
            print("Valid ELF magic")
            ei_class = data[4]
            if ei_class == 2:
                print("Class: 64-bit")
            elif ei_class == 1:
                print("Class: 32-bit")
            
            e_type = struct.unpack('<H', data[16:18])[0]
            e_machine = struct.unpack('<H', data[18:20])[0]
            e_entry = struct.unpack('<Q', data[24:32])[0]
            print(f"e_type: {e_type} (2=EXEC, 3=DYN)")
            print(f"e_machine: {e_machine} (62=x86_64)")
            print(f"e_entry: 0x{e_entry:x}")

            e_phoff = struct.unpack('<Q', data[32:40])[0]
            e_phnum = struct.unpack('<H', data[56:58])[0]
            e_phentsize = struct.unpack('<H', data[54:56])[0]
            e_shoff = struct.unpack('<Q', data[40:48])[0]
            e_shnum = struct.unpack('<H', data[60:62])[0]
            e_shentsize = struct.unpack('<H', data[58:60])[0]
            e_shstrndx = struct.unpack('<H', data[62:64])[0]
            
            print(f"Program Headers: offset={e_phoff}, num={e_phnum}, size={e_phentsize}")
            with open(filepath, 'rb') as f:
                for i in range(e_phnum):
                    f.seek(e_phoff + i * e_phentsize)
                    p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack('<IIQQQQQQ', f.read(56))
                    print(f"PH[{i}]: Type={p_type}, Flags={p_flags}, Offset=0x{p_offset:x}, VAddr=0x{p_vaddr:x}, PAddr=0x{p_paddr:x}, FileSz=0x{p_filesz:x}, MemSz=0x{p_memsz:x}")

            print(f"Section Headers: offset={e_shoff}, num={e_shnum}, size={e_shentsize}, strtab_idx={e_shstrndx}")
            
            # Read Section String Table first
            with open(filepath, 'rb') as f:
                f.seek(e_shoff + e_shstrndx * e_shentsize)
                sh_strtab_entry = f.read(e_shentsize)
                sh_offset = struct.unpack('<Q', sh_strtab_entry[24:32])[0]
                sh_size = struct.unpack('<Q', sh_strtab_entry[32:40])[0]
                
                f.seek(sh_offset)
                strtab = f.read(sh_size)
                
                # Read Section Headers
                f.seek(e_shoff)
                for i in range(e_shnum):
                    sh_data = f.read(e_shentsize)
                    sh_name_idx = struct.unpack('<I', sh_data[0:4])[0]
                    sh_type = struct.unpack('<I', sh_data[4:8])[0]
                    sh_flags = struct.unpack('<Q', sh_data[8:16])[0]
                    sh_addr = struct.unpack('<Q', sh_data[16:24])[0]
                    sh_offset = struct.unpack('<Q', sh_data[24:32])[0]
                    sh_size = struct.unpack('<Q', sh_data[32:40])[0]
                    
                    name = ""
                    if sh_name_idx < len(strtab):
                        name_end = strtab.find(b'\x00', sh_name_idx)
                        name = strtab[sh_name_idx:name_end].decode('utf-8', errors='ignore')
                    
                    print(f"SH[{i}] {name}: Type={sh_type}, Offset=0x{sh_offset:x}, Addr=0x{sh_addr:x}, Size=0x{sh_size:x}")
                    
        else:
            print("Not an ELF file")
            
    except Exception as e:
        print(f"Error reading file: {e}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        check_multiboot(sys.argv[1])
    else:
        print("Usage: python check_mb.py <file>")
