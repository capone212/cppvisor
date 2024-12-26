

def get_mapping():
    # 0       common  read                    sys_read

    result = {}
    with open('syscall_64.tbl') as input_file:
        for line in list(input_file):
            line = line.strip()
            if line == "" or line[0] == '#':
                continue
            parts = ' '.join(line.split()).split()
            if len(parts) != 4 or parts[1] == 'x32':
                continue
            syscall_no = int(parts[0])
            result[syscall_no] = parts[2]
    return result

def generate_header(mapping):
    headding = \
"""
#pragma once
#include <unordered_map>
#include <string>

inline static const std::unordered_map<int, std::string> SYS_CALL_MAP = {
"""

    footing = \
"""
}; 
"""
    with open("syscalls.h", "w") as file:
        file.write(headding)
        for number, name in mapping.items():
            file.write(f'   {{{number}, "{name}"}},\n')
        file.write(footing)

def main():
    mapping = get_mapping()
    generate_header(mapping)



if __name__ == '__main__':
    main()