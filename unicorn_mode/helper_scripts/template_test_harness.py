"""
    template_test_harness.py

    Template which loads the context of a process into a Unicorn Engine,
    instance, loads a custom (mutated) inputs, and executes the 
    desired code. Designed to be used in conjunction with one of the
    Unicorn Context Dumper scripts.

    Author:
        Nathan Voss <njvoss299@gmail.com>
"""

import argparse
import posix_ipc
import os
import struct
import numpy as np
import sys

from unicorn import *
from unicorn.x86_const import *  # TODO: Set correct architecture here as necessary

import unicorn_loader

# Simple stand-in heap to prevent OS/kernel issues
unicorn_heap = None

# Start and end address of emulation
START_ADDRESS = 0x804D4D5 # TODO: Set start address here
END_ADDRESS   = 0x804D4EF # TODO: Set end address here

# Address where checksum is checked and where it goes if it is valid
CHKSUM_CMP_ADDR    = 0x804DEF8
CHKSUM_PASSED_ADDR = 0x804DF05

# Entry points of addresses of functions to hook
MALLOC_ENTRY        = 0x8049D20
FREE_ENTRY          = 0x8049A40
PRINTF_ENTRY        = 0x804AC70
CGC_TRANSMIT_ENTRY  = 0x804A399
CGC_TRANSMIT_PASSED = 0x804A3B3

potential_address = {}
high_energy_address = {}

# TODO callflow generator output
potential_address[0x804d750] = 5000
potential_address[0x804d788] = 5000
potential_address[0x804d8fb] = 5000
potential_address[0x804d930] = 5000
potential_address[0x804db02] = 5000
potential_address[0x804db3a] = 5000
potential_address[0x804db78] = 5000
potential_address[0x804dc8e] = 5000
potential_address[0x804dd7e] = 5000
potential_address[0x804e052] = 5000

aflpro_shm_id = ''
input_content = ''

"""
    Implement target-specific hooks in here.
    Stub out, skip past, and re-implement necessary functionality as appropriate
"""
def unicorn_hook_instruction(uc, address, size, user_data):
    global aflpro_shm_id

    # deal with potential address here
    try:
        energy = potential_address[address]
        old_energy = read_shm()
        write_shm(old_energy + energy)
    except KeyError:
        pass

    # deal with `cmp` func here (high_energy_address)
    try:
        func_name = high_energy_address[address]
        energy = 0
        if func_name == 'memcmp':
            # TODO temporarily set compare string length is 12 bytes
            src = uc.mem_read(uc.reg_read(UC_X86_REG_ESP) + 8, 12)
            if src in input_content:
                energy += 100
        elif func_name == 'strcmp':
            src = uc.mem_read(uc.reg_read(UC_X86_REG_ESP) + 4, 12)
            dst = uc.mem_read(uc.reg_read(UC_X86_REG_ESP) + 8, 12)
            if src in input_content or dst in input_content:
                energy += 100
        old_energy = read_shm()
        write_shm(old_energy + energy)
    except KeyError:
        pass


    # TODO: Setup hooks and handle anything you need to here
    #    - For example, hook malloc/free/etc. and handle it internally
    if address == MALLOC_ENTRY:
        print("--- Rerouting call to malloc() @ 0x{0:08x} ---".format(address))
        size = struct.unpack("<I", uc.mem_read(uc.reg_read(UC_X86_REG_ESP) + 4, 4))[0]
        retval = unicorn_heap.malloc(size)
        uc.reg_write(UC_X86_REG_EAX, retval)
        uc.reg_write(UC_X86_REG_EIP, struct.unpack("<I", uc.mem_read(uc.reg_read(UC_X86_REG_ESP), 4))[0])
        uc.reg_write(UC_X86_REG_ESP, uc.reg_read(UC_X86_REG_ESP) + 4)

    # Bypass these functions by jumping straight out of them - We can't (or don't want to) emulate them
    elif address == FREE_ENTRY or address == PRINTF_ENTRY:
        print("--- Bypassing a function call that we don't want to emulate @ 0x{0:08x} ---".format(address))
        uc.reg_write(UC_X86_REG_EIP, struct.unpack("<I", uc.mem_read(uc.reg_read(UC_X86_REG_ESP), 4))[0])
        uc.reg_write(UC_X86_REG_ESP, uc.reg_read(UC_X86_REG_ESP) + 4)
    # Bypass the checksum check
    elif address == CHKSUM_CMP_ADDR:
        print("--- Bypassing checksum validation @ 0x{0:08x} ---".format(address))
        uc.reg_write(UC_X86_REG_EIP, CHKSUM_PASSED_ADDR)
    # Bypass the CGC_TRANSMIT_ENTRY check
    elif address == CGC_TRANSMIT_ENTRY:
        print("--- Bypassing CGC_TRANSMIT_ENTRY validation @ 0x{0:08x} ---".format(address))
        uc.reg_write(UC_X86_REG_EIP, CGC_TRANSMIT_PASSED)
    elif address == START_ADDRESS:
        print('>>> Tracing instruction at 0x%x, instruction size = 0x%x' %(address, size))
        print(uc.mem_read(address,size))



def read_shm():
    global aflpro_shm_id
    f = posix_ipc.SharedMemory(aflpro_shm_id)
    with os.fdopen(f.fd, 'rb') as ff:
        data = struct.unpack('<Q', ff.read())
        if len(data) > 0:
            print('--- Reading AflPro Share mem succeed: %s -> 0x%x ---' % (aflpro_shm_id, data[0]))
            return data[0]
    print('--- Reading AflPro Share mem FAILED: %s ---' % aflpro_shm_id)
    return -1


def write_shm(data):
    global aflpro_shm_id
    f = posix_ipc.SharedMemory(aflpro_shm_id)
    with os.fdopen(f.fd, 'wb') as ff:
        buf = bytearray(struct.pack('<Q', data))
        ff.write(buf)
    print('--- Writing to AflPro Share mem: %s -> 0x%x ---' % (aflpro_shm_id, data))


def ROL64(_x, _r):
    return ((_x << _r) | (_x >> (np.uint64(64) - _r)))


def ROL32(_x, _r):
    return ((_x << _r) | (_x >> (np.uint32(32) - _r)))


def hash64(key, length, seed):
    data = key
    h1 = np.uint64(seed ^ length)
    length >>= 3
    length -= 1
    i = 0
    while length >= 0:
        k1 = struct.unpack('<Q', data[0+i*8:8+i*8])[0]
        i += 1
        k1 = np.uint64(k1)
        k1 = k1 * np.uint64(0x87c37b91114253d5)
        k1 = ROL64(k1, np.uint64(31))
        k1 = k1 * np.uint64(0x4cf5ad432745937f)
        h1 ^= k1
        h1 = ROL64(h1, np.uint64(27))
        h1 = h1 * np.uint64(5) + np.uint64(0x52dce729)
        length -= 1
    h1 ^= h1 >> np.uint64(33)
    h1 *= np.uint64(0xff51afd7ed558ccd)
    h1 ^= h1 >> np.uint64(33)
    h1 *= np.uint64(0xc4ceb9fe1a85ec53)
    h1 ^= h1 >> np.uint64(33)
    return np.uint32(h1)


def hash32(key, length, seed):
    data = key
    h1 = np.uint32(seed ^ length)
    length >>= 2
    length -= 1
    i = 0
    while length >= 0:
        k1 = struct.unpack('<I', data[0+i*4:4+i*4])[0]
        i += 1
        k1 = np.uint32(k1)
        k1 = k1 * np.uint32(0xcc9e2d51)
        k1 = ROL32(k1, np.uint32(15))
        k1 = k1 * np.uint32(0x1b873593)
        h1 ^= k1
        h1 = ROL32(h1, np.uint32(13))
        h1 = h1 * np.uint32(5) + np.uint32(0xe6546b64)
        length -= 1
    h1 ^= h1 >> np.uint32(16)
    h1 *= np.uint32(0x85ebca6b)
    h1 ^= h1 >> np.uint32(13)
    h1 *= np.uint32(0xc2b2ae35)
    h1 ^= h1 >> np.uint32(16)
    return h1


def setup_aflpro_shm(testcase_content):
    global aflpro_shm_id
    if sys.maxsize > 2**32:
        aflpro_shm_id = '/' + str(hash64(testcase_content, len(testcase_content), 0xa5b35705)) + '.aflpro_shm'
    else:
        aflpro_shm_id = '/' + str(hash32(testcase_content, len(testcase_content), 0xa5b35705)) + '.aflpro_shm'
    f = posix_ipc.SharedMemory(aflpro_shm_id, flags=posix_ipc.O_CREAT, size=8, read_only=False)
    with os.fdopen(f.fd, 'wb') as f:
        buf = bytearray(struct.pack('<Q', 0))
        f.write(buf)
    print('[+] Setup AflPro Share mem succeed: %s' % aflpro_shm_id)

#------------------------
#---- Main test function

def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('context_dir', type=str, help="Directory containing process context")
    parser.add_argument('input_file', type=str, help="Path to the file containing the mutated input content")
    parser.add_argument('-d', '--debug', default=False, action="store_true", help="Dump trace info")
    args = parser.parse_args()

    print("Loading context from {}".format(args.context_dir))
    uc = unicorn_loader.AflUnicornEngine(args.context_dir, enable_trace=args.debug, debug_print=False)

    # Instantiate the hook function to avoid emulation errors
    global unicorn_heap
    unicorn_heap = unicorn_loader.UnicornSimpleHeap(uc, debug_print=True)
    uc.hook_add(UC_HOOK_CODE, unicorn_hook_instruction)

    # Execute 1 instruction just to startup the forkserver
    # NOTE: This instruction will be executed again later, so be sure that
    #       there are no negative consequences to the overall execution state.
    #       If there are, change the later call to emu_start to no re-execute
    #       the first instruction.
    print("Starting the forkserver by executing 1 instruction")
    try:
        uc.emu_start(START_ADDRESS, 0, 0, count=1)
    except UcError as e:
        print("ERROR: Failed to execute a single instruction (error: {})!".format(e))
        return

    # Allocate a buffer and load a mutated input and put it into the right spot
    if args.input_file:
        global input_content
        print("Loading input content from {}".format(args.input_file))
        input_file = open(args.input_file, 'rb')
        input_content = input_file.read()

        setup_aflpro_shm(input_content)
        input_file.close()

        # TODO: Apply constraints to mutated input here
        # if len(input_content) > 0xff:
        #     return
        # raise exceptions.NotImplementedError('No constraints on the mutated inputs have been set!')

        # Allocate a new buffer and put the input into it
        buf_addr = unicorn_heap.malloc(len(input_content))
        uc.mem_write(buf_addr, input_content)
        print("Allocated mutated input buffer @ 0x{0:016x}".format(buf_addr))

        # TODO: Set the input into the state so it will be handled
        uc.reg_write(UC_X86_REG_EAX, buf_addr)
        uc.reg_write(UC_X86_REG_DL, len(input_content))
        # raise exceptions.NotImplementedError('The mutated input was not loaded into the Unicorn state!')

    # Run the test
    print("Executing from 0x{0:016x} to 0x{1:016x}".format(START_ADDRESS, END_ADDRESS))
    try:
        result = uc.emu_start(START_ADDRESS, END_ADDRESS, timeout=0, count=0)
    except UcError as e:
        # If something went wrong during emulation a signal is raised to force this
        # script to crash in a way that AFL can detect ('uc.force_crash()' should be
        # called for any condition that you want AFL to treat as a crash).
        print("Execution failed with error: {}".format(e))
        uc.dump_regs()
        uc.force_crash(e)

    print("Final register state:")
    uc.dump_regs()

    print("Done.")

if __name__ == "__main__":
    main()
