import sys

# PE file standard offsets
OFF_NUMBER_OF_NAMES = 0x18
OFF_ADDRESS_OF_FUNCTIONS = 0x1c
OFF_ADDRESS_OF_NAMES = 0x20
OFF_ADDRESS_OF_NAME_ORDINALS = 0x24
OFF_NT_HEADER = 0x3c
OFF_EXPORT_DIR = 0x88

# EPROCESS offsets determined by fuzzing
OFF_STATE = 0x4
OFF_DTB = 0x28
OFF_NAME = 0
OFF_PID = 0
OFF_BLINK = 0
OFF_FLINK = 0
OFF_PPID = 0
EPROCESS_MAX_SIZE = 0x800
PID_MAX_VALUE = 0xFFFFFFFF


def virtual_to_physical(va, table_base):
    physical_offset = 0
    for i in range(4):
        physical_offset = table_base
        shift_offset = 12 + (3 - i) * 9
        table_offset = (va & (0x1ff << shift_offset)) >> (shift_offset - 3)
        # print ("table start at: {}, table_offset: {}".format(hex(table_base),hex(table_offset)))
        f.seek(table_base + table_offset)
        r = f.read(8)
        table_base = int.from_bytes(r, "little") & 0xffffffffff000
    return physical_offset + (0x1fffff & va)


def read_physical_little_endian(offset, size):
    f.seek(offset)
    ret = f.read(size)
    return int.from_bytes(ret, "little")


def read_virtual(va, cb, table_base):
    return read_physical_little_endian(virtual_to_physical(va, table_base), cb)


def get_ntoskrnl():
    global pa_dtb
    # Fetch Directory Base (DTB (PML4)) and initialize Memory Model.
    f.seek(0x1000)
    data = f.read(0x9f00)
    kernel_hint = int.from_bytes(data[0x70:0x78:], "little")
    kernel_base = kernel_hint & (~0x1fffff)
    pa_dtb = int.from_bytes(data[0xa0:0xa8:], "little")

    print("kernel base located at: " + hex(kernel_base))
    print("dtb located at: " + hex(pa_dtb))

    mz_physical_offset = 0
    # Scanning 32mb in 2mb chunks for the 'ntoskrnl' base address

    while (kernel_base + 0x2000000) > kernel_hint:
        mz_physical_offset = virtual_to_physical(kernel_base, pa_dtb)
        # print("virtual: {} to physical: {}".format(hex(kernel_base), hex(mz_physical_offset)))

        for i in range(0, 0x200000, 0x1000):
            f.seek(mz_physical_offset + i)
            expect_mz_read = f.read(2)

            if str(expect_mz_read) == "b'MZ'":
                mz_physical_offset += i
                kernel_base += i
                print("Found ntoskrnl.exe at va: {} and pa: {}".format(hex(kernel_base), hex(mz_physical_offset)))
                return kernel_base, mz_physical_offset
        kernel_base -= 0x200000


def find_offsets(pa_dtb, systemEProcess):
    global OFF_PPID, OFF_PID, OFF_NAME, OFF_BLINK, OFF_FLINK
    # Get The Name Offset
    for i in range(0, EPROCESS_MAX_SIZE, 8):
        name = read_virtual(systemEProcess + i, 8, pa_dtb)

        if name == 0x00006D6574737953:  # Look for System name
            OFF_NAME = i
            break

    # Get The Flink And Blink Offsets
    for i in range(0, EPROCESS_MAX_SIZE - 8, 8):
        pid = read_virtual(systemEProcess + i, 8, pa_dtb)
        if pid == 4:
            va1 = read_virtual(systemEProcess + i + 8, 8, pa_dtb) - i - 8

            process_name = read_virtual(va1 + OFF_NAME, 8, pa_dtb)
            #                   Secure System                           Registry                                smss.exe
            if process_name != 0x5320657275636553 and process_name != 0x7972747369676552 and process_name != 0x6578652e73736d73:
                continue
            OFF_PID = i
            OFF_FLINK = i + 8
            OFF_BLINK = i + 16
            break

    # find and read smss.exe
    smssEProcess = systemEProcess
    for i in range(6):
        smssEProcess = read_virtual(smssEProcess + OFF_FLINK, 8, pa_dtb) - OFF_FLINK
        smss_proc_name = read_virtual(smssEProcess + OFF_NAME, 8, pa_dtb)
        if smss_proc_name == 0x6578652e73736d73:  # smss.exe
            break

    # find offset for ParentPid (_EPROCESS!InheritedFromUniqueProcessId)
    # (parent pid is assumed to be located between BLink and Name
    for i in range(OFF_BLINK, OFF_NAME, 8):
        ppid_system = read_virtual(systemEProcess + i, 8, pa_dtb)
        ppid_smss = read_virtual(smssEProcess + i, 8, pa_dtb)
        if ppid_system == 0 and ppid_smss == 4:
            OFF_PPID = i
            break


def print_all_processes(eprocess):
    print("{:<8} {:<8} {:<10}".format('Pid', 'PPid', 'ImagePathName'))

    while True:
        pid = read_virtual(eprocess + OFF_PID, 8, pa_dtb)
        ppid = read_virtual(eprocess + OFF_PPID, 8, pa_dtb)
        if PID_MAX_VALUE < pid or PID_MAX_VALUE < ppid:
            break
        name = read_virtual(eprocess + OFF_NAME, 16, pa_dtb)
        final_name = ""
        for j in range(16):
            hex_val = ((0xff << j * 8) & name) >> (j * 8)
            if hex_val == 0x00:
                break
            final_name += chr(hex_val)
        print("{:<8} {:<8} {:<10}".format(pid, ppid, final_name))
        eprocess = read_virtual(eprocess + OFF_FLINK, 8, pa_dtb) - OFF_FLINK


def get_system_eprocess(va_kernel_base, mz_physical_offset):
    nt_header_offset = read_physical_little_endian(mz_physical_offset + OFF_NT_HEADER, 4)
    export_directory_offset = mz_physical_offset + nt_header_offset + OFF_EXPORT_DIR  # Export dir offset
    rva_ntos_export = read_physical_little_endian(export_directory_offset, 4)
    poffset_ntos_export = mz_physical_offset + rva_ntos_export

    number_of_names = read_physical_little_endian(poffset_ntos_export + OFF_NUMBER_OF_NAMES, 4)
    exported_rva_function_names = read_physical_little_endian(poffset_ntos_export + OFF_ADDRESS_OF_NAMES, 4)
    exported_rva_name_ordinals = read_physical_little_endian(poffset_ntos_export + OFF_ADDRESS_OF_NAME_ORDINALS, 4)
    exported_rva_functions_addresses = read_physical_little_endian(poffset_ntos_export + OFF_ADDRESS_OF_FUNCTIONS, 4)

    PsInitialSystemProcessOrdinal = 0
    for i in range(number_of_names):
        name_offset = read_physical_little_endian(mz_physical_offset + exported_rva_function_names + i * 4, 4)
        name = ""
        read = ""
        for j in range(255):
            read = chr(read_physical_little_endian(mz_physical_offset + name_offset + j, 1))
            if (read == '\x00'):
                break
            name += read
        # print (name)
        if (name == 'PsInitialSystemProcess'):
            print("found PsInitialSystemProcess in ordinal inex: {}".format(i))
            PsInitialSystemProcessOrdinal = i
            break

    function_offset = read_physical_little_endian(
        poffset_ntos_export + exported_rva_name_ordinals - rva_ntos_export + PsInitialSystemProcessOrdinal * 2, 2)
    psinitoffset = read_physical_little_endian(
        poffset_ntos_export + exported_rva_functions_addresses - rva_ntos_export + function_offset * 4, 4)
    PsInitialSystemProcessVA = va_kernel_base + psinitoffset
    systemEPROCESS = read_physical_little_endian(virtual_to_physical(PsInitialSystemProcessVA, pa_dtb), 8)
    return systemEPROCESS


def main():
    global f

    ram_path = sys.argv[1]
    f = open(ram_path, "rb")

    va_kernel_base, mz_physical_offset = get_ntoskrnl()
    system_eprocess = get_system_eprocess(va_kernel_base, mz_physical_offset)
    print("Found System EPROCESS at: {}", hex(system_eprocess))

    find_offsets(pa_dtb, system_eprocess)
    print_all_processes(system_eprocess)

    f.close()


if __name__ == '__main__':
    main()
