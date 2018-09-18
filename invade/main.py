"""invade main module.

Classes:
    Me: Contains information about the operating environment.
    Scout: Contains information about active processes.
    Target: Contains information about the target process.
    Tool: Contains common and miscellaneous methods.

Classes Me, Scout, and Target should only contain methods that will never
conceivably be used outside of each class. The Tool class should contain
miscellaneous methods that are freely and commonly used. As a result, the
Tool class is lengthy, but easy to navigate because of the method naming
convention.
"""


import sys
import platform
import struct
import binascii
import uuid
import subprocess

import pefile  # https://github.com/erocarrera/pefile
import capstone  # https://github.com/aquynh/capstone
import keystone  # https://github.com/keystone-engine/keystone

from .winapi import *
from .version import *


# Constants

X86_MC_INSN_MAX = 15  # Max number of bytes for a single x86 instruction


# Classes

class Me(object):
    """Contains information about the operating environment.

    Attributes:
        is_windows (bool): True if OS is Windows.
        is_x64 (bool): True if this process is 64-bit.
        is_windows_x64 (bool): True if this process is 64-bit.
        is_windows_admin (bool): True if this process is running with admin
            privileges.
        is_debug_privilege_enabled (bool): True if this process has granted
            itself debug privileges successfully.

    """

    def __init__(self):
        self.version = VERSION
        self.is_windows = Tool.is_windows()
        self.is_x64 = Tool.is_x64()
        self.is_windows_x64 = Tool.is_windows_x64()
        self.is_windows_admin = Tool.is_windows_admin()
        self.is_debug_privilege_enabled = False
        if Tool.set_debug_privilege():
            self.is_debug_privilege_enabled = True
        else:
            self.is_debug_privilege_enabled = False


class Scout(object):
    """Contains information about active processes.

    Typically, only one instance of Scout is used. However, you may want to
    use multiple Scout instances to compare process lists obtained at
    different times.

    Args:
        process_name (str): Name of the process, e.g. 'calc.exe'.
        case_sensitive (bool, optional): Whether the process name comparison
            should be case-sensitive.
        contains (bool, optional): Allows partial matching. If True, a partial
            process_name may return results.
        report_errors (bool): If True, errors will print.

    Attributes:
        process_name (str, optional): Name of the process, e.g. 'calc.exe'.
        report_errors (bool, optional): If True, errors will print.
        processes (list): A list of all running processes and their PIDs.
        pids (list): A list of all running process PIDs.

    """

    def __init__(self, process_name=None, case_sensitive=False, contains=False,
                 report_errors=True):
        self.process_name = process_name
        self.report_errors = report_errors
        self.processes = None
        self.processes = Tool.get_processes(True, report_errors)
        self.pids = None
        if process_name:
            self.pids = Tool.get_pids_by_process_name(process_name,
                                                      self.processes,
                                                      case_sensitive,
                                                      contains)


class Target(object):
    """Contains information about the target process.

    Target is typically used after finding the desired process with Scout.

    Args:
        pid (int): The PID of the process. Use Scout to obtain the PID.
        process_access_rights (int): Access rights for opening the process.
        process_name (str, optional): The name of the process, e.g. 'calc.exe'.
        report_errors (bool, optional): If True, errors are printed.

    Attributes:
        report_errors (bool): If True, errors are printed.
        pid (int): The PID of the process.
        process_access_rights (int): Access rights for opening the process.
        process_handle (int): The handle of the process.
        is_active (bool): If True, the process is running.
        is_x64 (bool): If True, the process is x64.
        base_address (int): The main executable's memory address.
        path (str): The file path of the process.
        version_info (list): File version information.
        entry_point_address (int): The relative address of the executable's
            entry point.
        process_name (str): The name of the process, e.g. 'calc.exe'.
        report_errors (bool): If True, errors are printed.

    """

    def __enter__(self):
        pass

    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            if self.process_handle:
                Tool.close_handle(self.process_handle)
        except AttributeError:
            pass

    def __init__(self, pid, process_access_rights=PROCESS_ALL_ACCESS,
                 process_name=None, report_errors=True):
        self._is_active = None
        self.report_errors = report_errors
        self.process_name = process_name
        self.pid = pid
        self.process_access_rights = process_access_rights
        self.process_handle = \
            Tool.get_process_handle_by_pid(pid, process_access_rights)
        self.is_x64 = None
        self.base_address = None
        self.path = None
        self.version_info = None
        self.entry_point_address = None

        if self.process_handle != 0:
            self.is_x64 = Tool.is_process_x64(self.process_handle)
            self.path = Tool.get_process_path_by_handle(self.process_handle,
                                                        False)
            if not self.path:
                self.path = Tool.get_process_path_by_pid(self.pid)
            if not self.process_name:
                if self.path:
                    self.process_name = self.path[self.path.rfind('\\') + 1:]
            if self.process_name:
                self.base_address = Tool.get_module_address(
                    self.process_handle, self.process_name)
            if self.base_address:
                if len(self.base_address) > 1 and self.report_errors:
                    # Not common, but possible
                    print(
                        f'Warning: multiple instances of {process_name} '
                        f'found in process')
                # Use first base address
                self.base_address = self.base_address[0]
            if self.path:
                self.version_info = Tool.pe_get_file_version(self.path)
                self.entry_point_address = \
                    Tool.pe_get_entry_point_address(self.path)
        else:
            self.process_handle = False

    @property
    def is_active(self):
        return self._is_active

    @is_active.getter
    def is_active(self):
        if hasattr(self, 'process_handle'):
            return Tool.is_process_active(self.process_handle)


class Tool(object):
    """Contains common and miscellaneous methods.

    """

    @staticmethod
    def memory_allocate(process_handle, size,
                        protection=PAGE_EXECUTE_READWRITE, address=None,
                        top_down=False):
        """Allocate a region of memory in the target process.

        Note:
            The PAGE_EXECUTE_READWRITE argument is default because it's
            convenient for shellcode to read and write to/from the same
            allocated area, even if potentially volatile in practice.
        """
        allocation_type = DWORD(MEM_COMMIT)
        if top_down:
            allocation_type = DWORD(MEM_COMMIT | MEM_TOP_DOWN)
        return VirtualAllocEx(process_handle, LPVOID(address), size,
                              allocation_type, DWORD(protection))

    @staticmethod
    def memory_free(process_handle, address, size=0, free_type=MEM_RELEASE):
        """Deallocate a region of memory  at a specified address and size.

        Note:
            MEM_RELEASE is likely the most common free type to be used with
            this module. From MSDN: "If the dwFreeType parameter is
            MEM_RELEASE, dwSize must be 0 (zero)."
        """
        VirtualFreeEx = kernel32.VirtualFreeEx
        if free_type == MEM_RELEASE:
            size = 0
        return VirtualFreeEx(process_handle, LPVOID(address), size,
                             DWORD(free_type))

    @staticmethod
    def memory_protect(process_handle, address, size,
                       protection=PAGE_EXECUTE_READWRITE):
        """Change a memory region's protection.

        Args:
            process_handle (int): A handle to the process.
            address (int): The memory region start address.
            size (int): The size of the region.
            protection (int, optional): The type of protection (a Windows
                memory protection constant). Default value is
                PAGE_EXECUTE_READWRITE because this is the most suitable for
                injected executable code / memory manipulation.

        Returns:
             int: The previous memory protection (a Windows memory protection
                constant).
        """
        protection_old = VirtualProtectEx(process_handle, LPVOID(address),
                                          size, protection, PDWORD(DWORD()))
        try:
            return protection_old.contents.value
        except AttributeError:
            pass

    @staticmethod
    def memory_read(process_handle, address, size, return_str=False):
        """Read data from a process's memory at a specified address and size.

        Args:
            process_handle (int): A handle to the process.
            address (int): The memory address to read at.
            size (int): Number of bytes to read.
            return_str (bool, optional): If True, the read bytes are returned
                as an uppercase string. Otherwise, they are returned as bytes.

        Returns:
            str: The bytes read from memory.
        """
        if not size:
            return

        data = create_string_buffer(size)
        number_of_bytes_read = c_size_t()

        if ReadProcessMemory(process_handle, LPVOID(address), data, size,
                             byref(number_of_bytes_read)):
            if return_str:
                return data.raw.hex().upper()
            else:
                return data.raw
        return

    @staticmethod
    def memory_read_pointers(process_handle, pointers, pointer_size,
                             report_errors=True):
        """Read through a series of memory pointers in another process.

        Args:
            process_handle (int): The handle of the process.
            pointers (str): A string representation of pointers,
                comma separated, to be sequentially read. The syntax is
                similar to assembly pointers. Addition, subtraction,
                multiplication, and division are supported using these
                operators: + - * /.
            pointer_size (int): The size of a memory pointer in the process.
                Use 4 if the process architecture is x86. Use 8 if x64.
            report_errors (bool, optional): If True, errors are printed.

        Returns:
            int: Final read address/value on success.

        Examples:
            The following explains pointers argument further:

            '[0x10000000],[+0x100]' Means to take the value at 0x10000000,
            add 100 bytes, go to that address, then return that value at
            that address.

            '[0x10000000],+0x100' means to take the value at 0x10000000,
            add 100 bytes, and return the value at that address.
        """
        if not pointer_size:
            if report_errors:
                print('Error: invalid pointer size')
            return

        pointers = pointers.replace(' ', '')
        pointers = pointers.split(',')
        # if len(pointers) < 2:
        #     if report_errors:
        #         print('Error: invalid pointer sequence')
        #     return

        i = -1
        current_address = None
        for s in pointers:
            i += 1  # Iteration count, starting with pointer item 0
            if '[' in s:
                # It's a pointer
                for c in '[]':  # Remove []
                    s = s.replace(c, '')
                operators = ['+', '-', '*', '/']
                if any(o in s for o in operators):
                    # It's an address pointer
                    if current_address is None:
                        # It's the first item
                        if report_errors:
                            print('Error: address sequence cannot begin with '
                                  'an address pointer')
                        return

                    operator = '+'  # Assume addition by default
                    if '-' in s:
                        operator = '-'
                    elif '*' in s:
                        operator = '*'
                    elif '/' in s:
                        operator = '//'

                    if '0x' in s:
                        try:
                            s = '0x' + str(format(int(s, 0), 'x'))
                        except ValueError:
                            if report_errors:
                                print(f'Error: error parsing item {i}')
                            return
                    else:
                        try:
                            s = str(int(s, 0))
                        except ValueError:
                            if report_errors:
                                print(f'Error: error parsing item {i}')
                            return

                    # Avoid -- (addition) by removing minus symbol
                    # Let operator do the work instead
                    s = s.replace('-', '')

                    try:
                        current_address = eval(
                            str(current_address) + operator + s)
                    except NameError:
                        if report_errors:
                            print(f'Error: error parsing item {i}')
                        return

                    current_address = Tool.memory_read(process_handle,
                                                       current_address,
                                                       pointer_size, False)
                    if not current_address:
                        if report_errors:
                            print(f'Error: memory read failure for item {i}')
                        return

                    current_address = int.from_bytes(current_address,
                                                     byteorder='little',
                                                     signed=False)

                else:
                    # It's a regular pointer
                    try:
                        s = int(s, 0)
                    except ValueError:
                        if report_errors:
                            print(f'Error: error parsing item {i}')
                        return

                    current_address = Tool.memory_read(process_handle, s,
                                                       pointer_size, False)
                    if not current_address:
                        if report_errors:
                            print(f'Error: memory read failure for item {i}')
                        return

                    current_address = int.from_bytes(current_address,
                                                     byteorder='little',
                                                     signed=False)

            else:
                # It's an address
                if current_address is None:
                    # It's the first item
                    try:
                        current_address = int(s, 0)
                    except ValueError:
                        if report_errors:
                            print(f'Error: error parsing item {i}')
                        return

                else:
                    # Assume addition by default
                    operator = '+'
                    if '-' in s:
                        operator = '-'
                    elif '*' in s:
                        operator = '*'
                    elif '/' in s:
                        operator = '//'

                    # Remove operators
                    for c in '+-*/':
                        s = s.replace(c, '')

                    try:
                        current_address = eval(
                            str(current_address) + operator + s)
                    except NameError:
                        if report_errors:
                            print(f'Error: error parsing item {i}')
                        return

        return current_address

    @staticmethod
    def memory_write(process_handle, address, data,
                     restore_memory_protection=True, report_errors=True):
        """Write data to a process's memory at a specified address.

        Args:
            process_handle (int): A handle to the process.
            address (int): The memory address to write to.
            data (str or bytes): Bytes to write, e.g. '9090' or b'\x90\x90'.
            restore_memory_protection (bool, optional): If True, the memory
                region's protection is restored after writing. Otherwise, the
                region's protection is set to PAGE_EXECUTE_READWRITE.
            report_errors (bool, optional): If True, errors are printed.

        Returns:
            int: The number of bytes written on success.
        """
        if hasattr(data, 'decode'):
            data = create_string_buffer(data)[:-1]
        elif type(data) is str:
            # Remove whitespace characters
            data = ''.join(data.split())
            try:
                data = create_string_buffer(bytes.fromhex(data))[:-1]
            except ValueError:
                if report_errors:
                    print('Error: a non-hexadecimal character was used')
                return
        else:
            if report_errors:
                print('Error: lpBuffer must be bytes or str type')
            return
        size = len(data)
        if not size:
            return

        number_of_bytes_written = c_size_t()

        old_protection = Tool.memory_protect(process_handle, address, size)

        result = WriteProcessMemory(process_handle, LPVOID(address), data,
                                    size, byref(number_of_bytes_written))

        if not result:
            return

        if restore_memory_protection:
            Tool.memory_protect(process_handle, address, size, old_protection)

        return number_of_bytes_written.value

    @staticmethod
    def search_file_pattern(path, pattern, start_address=0, chunk_size=0,
                            chunk_limit=0, find_all=True):
        """
        Yields addresses of matching byte patterns inside a file.

        Supports wildcard bytes, a starting address, reading in chunks, and
        read limits.

        Args:
            path (str): A file path.
            pattern (str): A sequence of bytes, e.g. 'FF ?? E8 26 23 D7'.
                '??' represents a single byte wildcard. Spaces between bytes
                are optional.
            start_address (int, optional): Search start address.
            chunk_size (int, optional): The read length per chunk. By default,
                chunks are not used and the entire file is read into memory.
            chunk_limit (int, optional): The maximum number of chunks to read.
                By default, all chunks are read.
            find_all (bool, optional): If True, all found instances are
                yielded. If False, only the first found instance is yielded
                and searching stops.

        Yields:
            int: Found address.

        Example:
            import invade
            found_addresses = []
            for found_address in tool.search_file_pattern(
                    r'C:\target.exe',
                    '?? 01 55 ?? ?? 4B 20 1E 1D ?? 15',
                    start_address=0x1000,
                    chunk_size=1024,
                    chunk_limit=10,
                    find_all=False):
                found_addresses.append(found_address)
            for address in found_addresses:
                print(hex(address))
        """

        # Remove whitespace characters
        pattern = ''.join(pattern.split())

        # If no path, invalid pattern, or pattern is all wildcards.
        if not path or len(pattern) < 2 or len(
                pattern) % 2 != 0 or pattern.count('?') == len(pattern):
            return

        # If chunk_size is 0, the whole file should be read.
        if chunk_size == 0:
            chunk_size = -1

        # Simplifies later chunk_size comparison.
        if chunk_limit == 0:
            chunk_limit = -1

        # Get largest segment bytes.
        pattern_largest_segment = list(filter(None, pattern.split('??')))
        pattern_largest_segment.sort(key=len, reverse=True)
        pattern_largest_segment = pattern_largest_segment[0]
        pattern_largest_segment_position = pattern.index(
            pattern_largest_segment) // 2
        pattern_largest_segment = bytes.fromhex(pattern_largest_segment)

        # Search method 1 (no wildcards).
        if pattern.count('?') == 0:
            pattern_bytes = bytes.fromhex(pattern)
            chunk_position = 0
            with open(path, 'rb') as f:
                if start_address > 0:
                    f.seek(start_address)
                while True:
                    if chunk_limit > 0:
                        if chunk_position / chunk_size >= chunk_limit:
                            return
                    try:
                        data = f.read(chunk_size)
                    except MemoryError:
                        return
                    if not data:
                        return
                    i = 0
                    found_position = 0
                    while True:
                        try:
                            found_position = data.index(pattern_bytes,
                                                        found_position + i)
                            if chunk_size > 0:
                                yield chunk_position + found_position + \
                                      start_address
                            else:
                                yield found_position + start_address
                            if find_all is False:
                                return
                        except ValueError:
                            break
                        i += 1
                    chunk_position += chunk_size
                    continue

        # Create a list of wildcard positions.
        pattern_wildcard_positions = []
        for i in range(0, len(pattern), 2):
            pattern_byte = pattern[i:i + 2]
            if pattern_byte == '??':
                pattern_wildcard_positions.append(i // 2)

        # Remove wildcards from pattern string and convert to bytes.
        pattern_len = len(pattern) // 2
        pattern_bytes = pattern.replace('?', '')
        pattern_bytes = bytes.fromhex(pattern_bytes)

        # Search method 2 (wildcards).
        possible_positions = []
        end_of_file = False
        first_result = True
        chunk_position = 0

        with open(path, 'rb') as f:
            if start_address > 0:
                f.seek(start_address)
            while not end_of_file:
                if chunk_limit > 0:
                    if chunk_position / chunk_size >= chunk_limit:
                        return
                try:
                    data = f.read(chunk_size)
                except MemoryError:
                    return
                if not data:
                    end_of_file = True
                chunk_search = True
                while chunk_search:
                    try:
                        if first_result is True:
                            possible_positions.append(
                                data.index(pattern_largest_segment))
                            first_result = False
                        else:
                            possible_positions.append(
                                data.index(pattern_largest_segment,
                                           possible_positions[-1] + 1))
                    except ValueError:
                        if chunk_size > 0:
                            chunk_position += chunk_size
                        chunk_search = False
                for possible_position in possible_positions:
                    possible_position -= pattern_largest_segment_position
                    match_count = 0
                    pattern_bytes_pos = 0
                    data_offset_pos = 0
                    i = 0
                    while i < pattern_len:
                        if i in pattern_wildcard_positions:
                            match_count += 1
                            data_offset_pos += 1
                            i += 1
                            continue
                        if possible_position < 0:
                            possible_position = 0
                        if pattern_bytes[pattern_bytes_pos] == data[
                                    possible_position + data_offset_pos]:
                            match_count += 1
                            data_offset_pos += 1
                            pattern_bytes_pos += 1
                            i += 1
                            continue
                        i += 1
                    if match_count == pattern_len:
                        if find_all is True:
                            if chunk_size > 0:
                                yield chunk_position + possible_position + \
                                      start_address - chunk_size
                            else:
                                yield possible_position + start_address
                        else:
                            yield possible_position + chunk_position + \
                                  start_address - chunk_size
                            return
                possible_positions = []
                first_result = True
            return

    @staticmethod
    def run_app(path, wait=False):
        """Run an application.

        If wait is False, execution will resume when the program or file is
        closed.
        """
        if not wait:
            subprocess.Popen(path)  # Default, no wait
            return True
        subprocess.run(path)  # Waits until completion
        return True

    @staticmethod
    def create_random_str_hex(length=32, lowercase=True):
        """Create random hex string. Default length is 32 characters.

        Example output: '409b9a6713b9469aac473755c8cc064a'
        """
        str_hex = ''
        i = 0
        while i < length:
            str_hex += str(uuid.uuid4()).replace('-', '')
            i += len(str_hex)
        if lowercase is False:
            str_hex = str_hex.upper()
        return str_hex[:length]

    @staticmethod
    def pe_get_entry_point_address(path):
        """Get an executable's entry point address via PE header."""
        pe = pefile.PE(path, fast_load=True)
        try:
            return pe.OPTIONAL_HEADER.AddressOfEntryPoint
        except (AttributeError, KeyError):
            return

    @staticmethod
    def pe_get_rva_diff(path):
        """Get the RVA difference between file in memory vs. file on disk.

        0xc00 (3072) is a common return value.
        """
        pe = pefile.PE(path, fast_load=True)
        try:
            return pe.OPTIONAL_HEADER.BaseOfCode - \
                   pe.OPTIONAL_HEADER.SizeOfHeaders
        except (AttributeError, KeyError):
            return

    @staticmethod
    def pe_get_file_version(path):
        """Get an executable's version information via PE header."""
        version_info = {
            'file_version_1': None,
            'product_version_1': None,
            'file_version_2': None,
            'product_version_2': None,
            'major_image_version': None,
            'minor_image_version': None,
        }

        f = pefile.PE(path, fast_load=True)
        f.parse_data_directories(
            directories=[
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])

        try:
            for a in f.FileInfo:
                for b in a:
                    if b.name == 'StringFileInfo':
                        for c in b.StringTable:
                            version_info['file_version_1'] = \
                                c.entries[b'FileVersion'].decode()
                            version_info['product_version_1'] = \
                                c.entries[b'ProductVersion'].decode()
                            break
        except (AttributeError, KeyError):
            pass

        try:
            file_version_ms = f.VS_FIXEDFILEINFO.FileVersionMS
            file_version_ls = f.VS_FIXEDFILEINFO.FileVersionLS
            version_info['file_version_2'] = \
                f'{file_version_ms >> 16}' \
                f'.{file_version_ms & 0xFFFF}' \
                f'.{file_version_ls >> 16}' \
                f'.{file_version_ls & 0xFFFF}'
            product_version_ms = f.VS_FIXEDFILEINFO.ProductVersionMS
            product_version_ls = f.VS_FIXEDFILEINFO.ProductVersionLS
            version_info['product_version_2'] = \
                f'{product_version_ms >> 16}' \
                f'.{product_version_ms & 0xFFFF}' \
                f'.{product_version_ls >> 16}' \
                f'.{product_version_ls & 0xFFFF}'
        except (AttributeError, KeyError):
            pass

        try:
            version_info['major_image_version'] = \
                f.OPTIONAL_HEADER.MajorImageVersion
            version_info['minor_image_version'] = \
                f.OPTIONAL_HEADER.MinorImageVersion
        except (AttributeError, KeyError):
            pass

        return version_info

    @staticmethod
    def pe_get_export_symbol_address(symbol, path, include_base=False,
                                     case_sensitive=False):
        """Get a symbol's address inside a PE file.

        Commonly used to find the address of a function inside a DLL file.

        Args:
            symbol (str): The name of the symbol, i.e. 'MessageBoxW'.
            path (str): Path to PE file.
            include_base (bool, optional): If True, the executable's base
                address is is added to the symbol's address.
            case_sensitive (bool, optional): Whether the process name
                comparison should be case-sensitive.

        Returns:
            list: A list of symbol addresses.
        """
        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])
        symbol_addresses = []
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            try:
                if exp.name.decode().lower() == symbol.lower():
                    if case_sensitive:
                        if exp.name.decode() == symbol:
                            if include_base:
                                symbol_addresses.append(
                                    exp.address + pe.OPTIONAL_HEADER.ImageBase)
                            else:
                                symbol_addresses.append(exp.address)
                    else:
                        if include_base:
                            symbol_addresses.append(
                                exp.address + pe.OPTIONAL_HEADER.ImageBase)
                        else:
                            symbol_addresses.append(exp.address)
            except AttributeError:
                pass
        if symbol_addresses:
            return symbol_addresses

    @staticmethod
    def pe_get_code_cave_end_of_section(path, section_name='.text'):
        """Get the end-of-section code cave info for a specific PE section.

        A code cave is a portion of memory that can be used for executing
        custom (injected) instructions. The end of a PE section often contains
        a block of zeroed memory. This area of memory can be easier to use
        because there is often no need to allocate new memory or change
        memory region protection. The information returned from this function
        can be used to find a home for injected code. A list is returned
        because it is possible that multiple sections with the same name are
        present.

        Note:
            Packed files with altered section information may be incompatible.

        Args:
            path (str): Windows path to PE file.
            section_name (str, optional): Name of section, defaults to '.text'.

        Returns:
            list: Contains code cave information, i.e.
                [{'start': int, 'end': int, 'size': int}]
        """
        pe = pefile.PE(path, fast_load=True)
        section_code_cave = []
        for section in pe.sections:
            try:
                if section.Name.decode().strip('\0') == section_name:
                    section_alignment = pe.OPTIONAL_HEADER.SectionAlignment
                    section_virtual_size = section.Misc_VirtualSize
                    section_virtual_address = section.VirtualAddress

                    section_code_cave_start = \
                        section_virtual_size + section_virtual_address
                    section_code_cave_end = int(section_alignment * round(
                        float(section_code_cave_start) / section_alignment) +
                                                section_alignment - 1)
                    section_code_cave_size = \
                        section_code_cave_end - section_code_cave_start

                    section_code_cave.append({'start': section_code_cave_start,
                                              'end': section_code_cave_end,
                                              'size': section_code_cave_size})
            except AttributeError:
                pass
        if section_code_cave:
            return section_code_cave

    @staticmethod
    def get_asm(is_x64, mc, address=0):
        """Get assembly from Capstone for a string of machine code bytes.

        Args:
            is_x64 (bool): Generate assembly in 64-bit or 32-bit mode.
            mc (str): A string of machine code such as '55 8B EC 56'.
            address (int, optional): The address of where the code would be.
                This typically would be a memory address to ensure correct
                instruction calculation.

        Returns:
            list: A list of dicts containing disassembly information.
        """
        try:
            mc = bytes(bytearray.fromhex(mc))
        except ValueError:
            return
        if type(is_x64) is not bool:
            return
        mode = capstone.CS_MODE_64
        if not is_x64:
            mode = capstone.CS_MODE_32
        cs = capstone.Cs(capstone.CS_ARCH_X86, mode)
        asm = []
        try:
            for (address, size, mnemonic, op_str) in \
                    cs.disasm_lite(mc, address):
                asm.append({
                    'addr': address,
                    'size': size,
                    'asm': f'{mnemonic} {op_str}'
                })
            return asm
        except capstone.CsError:
            return

    @staticmethod
    def get_mc(is_x64, asm, address=0):
        """Get machine code bytes from Keystone for a string of assembly
        instructions.

        Args:
            is_x64 (bool): Generate machine code in 64-bit or 32-bit mode.
            asm (str): A string of assembly. Use ; or \n to delimit commands,
                e.g. 'mov eax, ebx;jmp 0xd46694'.
            address (int, optional): The address of where the code would be.
                This typically would be a memory address to ensure correct
                instruction calculation.

        Returns:
            str: A string of machine code bytes on success.
        """
        if type(asm) is not str:
            return
        if type(is_x64) is not bool:
            return
        mode = keystone.KS_MODE_64
        if not is_x64:
            mode = keystone.KS_MODE_32
        try:
            ks = keystone.Ks(keystone.KS_ARCH_X86, mode)
            asm_bytes = asm.encode()
            mc, mc_size = ks.asm(asm_bytes, address)
            result = Tool.convert_list_int_to_str_hex(mc)
            if result:
                return result
        except keystone.KsError:
            return

    @staticmethod
    def get_mc_size(s):
        """Get the number of bytes in a hex string."""
        s = ''.join(s.split())
        if Tool.is_str_hexadecimal(s):
            return int(len(s) / 2)
        return len(s)

    @staticmethod
    def get_processes(file_name_only=True, report_errors=True):
        """Get a list of all running processes and their PIDs.

        Args:
            file_name_only (bool, optional): return only file names, no paths.
            report_errors (bool, optional): if True, errors are printed.

        Returns:
            list: A list containing containing process names and PIDs on
            success.
        """
        try:
            EnumProcesses = psapi.EnumProcesses
        except AttributeError:
            EnumProcesses = kernel32.EnumProcesses

        process_buffer_size = 8192
        process_buffer_size_current = process_buffer_size
        process_buffer_size_max = 10 * 1024 * 1024

        while True:
            pProcessIds = (DWORD * process_buffer_size)()
            pBytesReturned = DWORD()
            if EnumProcesses(byref(pProcessIds), ctypes.sizeof(pProcessIds),
                             byref(pBytesReturned)):
                if pBytesReturned.value == process_buffer_size_current:
                    process_buffer_size_current += process_buffer_size
                elif process_buffer_size_current >= process_buffer_size_max:
                    if report_errors:
                        print(
                            'Error: number of processes exceeds buffer limit')
                        return
                else:
                    break
            else:
                if report_errors:
                    print('Error: EnumProcesses')
                    return

        QueryFullProcessImageName = kernel32.QueryFullProcessImageNameW
        processes = []

        for i in range(pBytesReturned.value // sizeof(DWORD)):
            dwProcessId = pProcessIds[i]
            hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False,
                                   dwProcessId)
            if hProcess:
                lpExeName = (c_wchar * MAX_PATH)()
                lpdwSize = DWORD(MAX_PATH)
                if QueryFullProcessImageName(hProcess, 0, byref(lpExeName),
                                             byref(lpdwSize)):
                    lpExeName = lpExeName.value
                    if file_name_only:
                        lpExeName = lpExeName[lpExeName.rfind('\\') + 1:]
                    processes.append([lpExeName, dwProcessId])
                CloseHandle(hProcess)
        return processes

    @staticmethod
    def get_process_handle_by_pid(pid, process_access_rights):
        """Get process's handle via the process's PID."""
        return OpenProcess(process_access_rights, False, pid)

    @staticmethod
    def get_process_path_by_handle(process_handle, report_errors=True):
        """Get processes's path via the process's handle."""
        try:
            GetModuleFileNameEx = psapi.GetModuleFileNameExW
        except AttributeError:
            GetModuleFileNameEx = kernel32.GetModuleFileNameExW

        lpFilename = (c_wchar * MAX_PATH)()
        nSize = sizeof(lpFilename)

        if GetModuleFileNameEx(process_handle, None, lpFilename, nSize):
            return lpFilename.value
        else:
            if report_errors:
                print('Error: cannot determine file path')
            return

    @staticmethod
    def get_process_path_by_pid(pid, report_errors=True):
        """Get process's path via the process's PID."""
        QueryFullProcessImageName = kernel32.QueryFullProcessImageNameW
        hProcess = Tool.get_process_handle_by_pid(pid,
                                                  PROCESS_QUERY_INFORMATION)
        dwFlags = DWORD()
        lpExeName = (c_wchar * MAX_PATH)()
        lpdwSize = DWORD(sizeof(lpExeName))
        if QueryFullProcessImageName(hProcess, dwFlags, lpExeName,
                                     byref(lpdwSize)):
            CloseHandle(hProcess)
            return lpExeName.value
        CloseHandle(hProcess)
        if report_errors:
            print('Error: cannot determine file path')
        return

    @staticmethod
    def get_pids_by_process_name(process_name, process_list,
                                 case_sensitive=False, contains=False):
        """Get a list of PIDs for the given process name.

        Args:
            process_name (str): The name of process, i.e. 'calc.exe'.
            process_list (list): A list of processes obtained from
                get_processes().
            case_sensitive (bool, optional): Whether the process name
                comparison should be case-sensitive.
            contains (bool, optional): Allows partial matching. If True, a
                partial process_name may return results.

        Returns:
            list: A list of int PIDs on success.
        """
        pids = []
        for i in range(len(process_list)):
            if case_sensitive:
                if contains:
                    if process_name in process_list[i][0]:
                        pids.append(process_list[i][1])
                else:
                    if process_list[i][0] == process_name:
                        pids.append(process_list[i][1])
            else:
                if contains:
                    if process_name.lower() in process_list[i][0].lower():
                        pids.append(process_list[i][1])
                else:
                    if process_list[i][0].lower() == process_name.lower():
                        pids.append(process_list[i][1])
        if pids:
            return pids
        else:
            return

    @staticmethod
    def get_modules(process_handle, file_name_only=True,
                    report_errors=True):
        """Get a list of module information for a given process (each module's
        base address, size, etc.).

        Note:
            EnumProcessModulesEx will fail when called on a 64-bit target
            from 32-bit.

        Args:
            process_handle (int): A process handle.
            file_name_only (bool, optional): If True, list will contain only
                file names; no paths.
            report_errors (bool, optional): If True, errors are printed.

        Returns:
            list: A list of strings on success.

        """
        try:
            EnumProcessModulesEx = psapi.EnumProcessModulesEx
        except AttributeError:
            EnumProcessModulesEx = kernel32.EnumProcessModulesEx

        module_buffer_size = 1024
        lpcbNeeded = DWORD(module_buffer_size)
        data_type_size = sizeof(HMODULE)

        while True:
            lphModule = (HMODULE * (module_buffer_size // data_type_size))()
            if EnumProcessModulesEx(process_handle, byref(lphModule),
                                    lpcbNeeded,
                                    byref(lpcbNeeded), LIST_MODULES_ALL):
                if lpcbNeeded.value <= module_buffer_size:
                    break
                module_buffer_size = lpcbNeeded.value
            else:
                if report_errors:
                    print('Error: EnumProcessModulesEx')
                    return

        try:
            GetModuleInformation = psapi.GetModuleInformation
        except AttributeError:
            GetModuleInformation = kernel32.GetModuleInformation

        module_list = []

        for hModule in lphModule:
            # GetMappedFileName is better than GetModuleFileNameEx in
            # this instance.
            try:
                GetMappedFileName = psapi.GetMappedFileNameW
            except AttributeError:
                GetMappedFileName = kernel32.GetMappedFileNameW

            lpFilename = (c_wchar * MAX_PATH)()
            nSize = sizeof(lpFilename)

            if GetMappedFileName(process_handle, LPVOID(hModule), lpFilename,
                                 nSize):

                lpmodinfo = MODULEINFO()
                if GetModuleInformation(process_handle, LPVOID(hModule),
                                        byref(lpmodinfo), sizeof(lpmodinfo)):

                    if file_name_only:
                        lpFilename = lpFilename.value[
                                     lpFilename.value.rfind('\\') + 1:]

                    module_list.append(
                        [lpFilename, lpmodinfo.lpBaseOfDll,
                         lpmodinfo.SizeOfImage,
                         lpmodinfo.EntryPoint])

                else:
                    if report_errors:
                        print('Error: GetModuleInformation')

            else:
                if report_errors:
                    pass
                    # This will likely occur multiple times if not admin.
                    # print('Error: GetMappedFileName')

        if module_list:
            return module_list

    @staticmethod
    def get_module_address(process_handle, module_name, case_sensitive=False):
        """Get a list of base addresses for the given module name.

        Note:
            Multiple base addresses will be returned when modules with the
            same name are present.
        """
        results = []
        process_modules = Tool.get_modules(process_handle)
        if process_modules:
            for a in process_modules:
                if case_sensitive:
                    if a[0] == module_name:
                        results.append(a[1])
                else:
                    if a[0].lower() == module_name.lower():
                        results.append(a[1])
        if results:
            return results

    @staticmethod
    def get_module_path(process_handle, module_name, dos_paths=False,
                        case_sensitive=False):
        """Get a list of paths for a given module name.

        Using a supplied process handle and the name of a module (usually a
        .dll file), the Windows path to the file us returned. A list is
        always returned because it is always possible that multiple instances
        of a module are present in memory.

        Args:
            process_handle (int): A process handle.
            module_name (str): The module's file name, e.g. 'kernel32.dll'.
            dos_paths (bool, optional): If False, regular Windows paths are
                returned. If True, MS-DOS device names are returned.
            case_sensitive (bool, optional): Whether the module name
                comparison should be case-sensitive.

        Returns:
            list: A list of module names on success.
        """
        module_paths_dos = []
        process_modules = Tool.get_modules(process_handle, False)
        if process_modules:
            for m in process_modules:
                if case_sensitive:
                    if m[0].value[m[0].value.rfind('\\') + 1:] == module_name:
                        module_paths_dos.append(m[0].value)
                else:
                    if m[0].value[m[0].value.rfind(
                            '\\') + 1:].lower() == module_name.lower():
                        module_paths_dos.append(m[0].value)

        if dos_paths:
            if module_paths_dos:
                return module_paths_dos
            return

        module_paths = []
        for m in module_paths_dos:
            module_path = Tool.convert_dos_path_to_drive_path(m)
            if module_path:
                module_paths.append(module_path)
            else:
                return
        if module_paths:
            return module_paths
        return

    @staticmethod
    def get_drive_paths(report_errors=True):
        """Get a list of drive paths in multiple formats.

        A list is returned containing each drive's assigned letter, MS-DOS
        device name and volume GUID. This function is Primarily used by
        Tool.convert_dos_path_to_drive_path() and can also be used for
        determining the number of connected drives.

        Args:
            report_errors (bool, optional): If True, errors will print.

        Returns:
            list: Contains drive information.
        """
        volume_guid_paths = []

        FindFirstVolume = kernel32.FindFirstVolumeW
        FindNextVolume = kernel32.FindNextVolumeW
        FindVolumeClose = kernel32.FindVolumeClose

        FindFirstVolume.restype = HANDLE
        lpszVolumeName = (c_wchar * MAX_PATH)()
        cchBufferLength = DWORD(sizeof(lpszVolumeName))
        hFindVolume = FindFirstVolume(lpszVolumeName, cchBufferLength)
        if hFindVolume == INVALID_HANDLE_VALUE:
            if report_errors:
                print('Error: FindFirstVolume returned an invalid handle')
            return
        volume_guid_paths.append(lpszVolumeName.value)

        # FindNextVolume only seems to work when HANDE restype is applied and
        # its return value is cast to HANDLE.
        hFindVolume = ctypes.cast(hFindVolume, HANDLE)
        while FindNextVolume(hFindVolume, lpszVolumeName, cchBufferLength):
            if lpszVolumeName.value[:4] != '\\\\?\\' or lpszVolumeName.value[
                                                        -1:] != '\\':
                continue
            volume_guid_paths.append(lpszVolumeName.value)

        if not len(volume_guid_paths):
            if report_errors:
                print('Error: no volumes present')
            return

        FindVolumeClose(hFindVolume)

        volume_path_names = []
        GetVolumePathNamesForVolumeName = \
            kernel32.GetVolumePathNamesForVolumeNameW
        lpszVolumePathNames = (
            c_wchar * MAX_PATH)()
        cchBufferLength = DWORD(sizeof(lpszVolumePathNames))
        lpcchReturnLength = DWORD()

        for volume_guid_path in volume_guid_paths:
            if GetVolumePathNamesForVolumeName(volume_guid_path,
                                               lpszVolumePathNames,
                                               cchBufferLength,
                                               lpcchReturnLength):
                volume_path_names.append(lpszVolumePathNames.value)

        if not len(volume_path_names):
            if report_errors:
                print('Error: no volumes present')
            return

        QueryDosDevice = kernel32.QueryDosDeviceW
        lpTargetPath = (c_wchar * MAX_PATH)()
        ucchMax = sizeof(lpTargetPath)
        dos_names = []
        for volume_guid_path in volume_guid_paths:
            if QueryDosDevice(volume_guid_path[4:-1], lpTargetPath, ucchMax):
                dos_names.append(lpTargetPath.value)

        if len(volume_guid_paths) != len(volume_path_names) != len(dos_names):
            if report_errors:
                print('Error: device inconsistency')
            return

        return [[volume_path_names[i], dos_names[i], volume_guid_paths[i]] for
                i in range(len(volume_guid_paths))]

    @staticmethod
    def set_debug_privilege(pid=None):
        """Set the debug privilege to allow greater access to other processes.

        This function is adapted from Cuckoo Sandbox:
        https://cuckoosandbox.org. Licensed under the GNU General Public
        License v3 (GPL-3). Changes: made function independent and compatible.
        """
        if pid is None:
            h_process = kernel32.GetCurrentProcess()
        else:
            h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)

        if not h_process:
            return

        h_current_token = HANDLE()
        if not advapi32.OpenProcessToken(h_process,
                                         TOKEN_ALL_ACCESS,
                                         pointer(h_current_token)):
            return

        se_original_luid = LUID()
        if not advapi32.LookupPrivilegeValueW(None, 'SeDebugPrivilege',
                                              pointer(se_original_luid)):
            return

        luid_attributes = LUID_AND_ATTRIBUTES()
        luid_attributes.Luid = se_original_luid
        luid_attributes.Attributes = SE_PRIVILEGE_ENABLED
        token_privs = TOKEN_PRIVILEGES()
        token_privs.PrivilegeCount = 1
        token_privs.Privileges = luid_attributes

        if not advapi32.AdjustTokenPrivileges(h_current_token, False,
                                              pointer(token_privs),
                                              0, None, None):
            return

        CloseHandle(h_current_token)
        CloseHandle(h_process)
        return True

    @staticmethod
    def close_handle(handle):
        return CloseHandle(handle)

    @staticmethod
    def is_windows():
        return sys.platform == 'win32'

    @staticmethod
    def is_windows_x64():
        return platform.machine().endswith('64')

    @staticmethod
    def is_windows_admin():
        try:
            return bool(shell32.IsUserAnAdmin())
        except AttributeError:
            return None  # In case of deprecation

    @staticmethod
    def is_x64():
        return True if sys.maxsize > 2 ** 32 else False

    @staticmethod
    def is_process_x64(process_handle):
        """Check if target process is x64 or x86. For insight, see MSDN's
        description of IsWow64Process.
        """
        try:
            IsWow64Process = kernel32.IsWow64Process
        except AttributeError:
            return

        _is_wow64 = BOOL(False)
        _is_windows_x64 = Tool.is_windows_x64()

        if IsWow64Process(process_handle, byref(_is_wow64)):
            if _is_windows_x64 is False:
                return False
            elif _is_wow64.value:
                return False
            return True
        return

    @staticmethod
    def is_process_active(process_handle):
        """Check if process with the given process handle is active."""
        GetExitCodeProcess = kernel32.GetExitCodeProcess
        lpExitCode = DWORD()
        if GetExitCodeProcess(process_handle, pointer(lpExitCode)):
            if lpExitCode.value != STILL_ACTIVE:
                return False
            return True

    @staticmethod
    def is_service_active(service_name):
        """Check if a service is active."""
        try:
            result = subprocess.run(
                f'sc query "{service_name}" | find "RUNNING"',
                shell=True, check=True, stdout=subprocess.PIPE)
            if not result:
                return False
            if 'RUNNING' in str(result.stdout):
                return True
            return False
        except (subprocess.CalledProcessError, AttributeError):
            return False

    @staticmethod
    def is_valid_address_x86(i):
        """Check if int is within a valid Windows x86 memory range."""
        return 0x10000 <= i <= 0x7FFFFFFF

    @staticmethod
    def is_valid_address_x64(i):
        """Check if int is within a valid Windows x64 memory range."""
        return 0x10000 <= i < 0x7FFFFFFFFFFF

    @staticmethod
    def is_str_hexadecimal(s):
        """Check if a string is a hexadecimal byte string.

        For example, '909090' returns True.

        Note:
            By design, hexadecimal strings with a length of 1 will return
            False. isalnum() will check for operators like + and - that would
            normally successfully validate.
        """
        if s.isalnum():
            if len(s) % 2 == 0:
                try:
                    return isinstance(int(s, 16), int)
                except ValueError:
                    pass
        return False

    @staticmethod
    def convert_dos_path_to_drive_path(dos_path, report_errors=True):
        drive_paths = Tool.get_drive_paths(report_errors)
        for drive_path in drive_paths:
            try:
                if dos_path.index(drive_path[1]) == 0:
                    return dos_path.replace(drive_path[1],
                                            drive_path[0]).replace('\\\\',
                                                                   '\\')
            except ValueError:
                continue
        return

    @staticmethod
    def convert_list_int_to_str_hex(l):
        """Converts a list of int values into a string of hex values.

        Useful for converting the return value of Keystone's asm() method into
        a str that can be used when writing memory.
        """
        return ''.join('%02X' % i for i in l)

    @staticmethod
    def convert_int_pointer_to_str_hex(i):
        """Converts a memory pointer integer to hex pointer string.

        For example, if i = 73588229205, '5544332211' is returned. The int is
        converted to hex string (with '0x' omitted) and then reversed. This is
        useful for obtaining hex pointers which are represented in memory in
        little endian format. Note that if the hex string has an odd length
        (e.g. '22b'), a '0' is padded to the last byte string so that '0b22' is
        returned.
        """
        str_hex = f'{i:02x}'
        if len(str_hex) % 2:
            str_hex = str_hex[:-1] + '0' + str_hex[-1:]
        str_hex = bytearray.fromhex(str_hex)
        str_hex.reverse()
        return str_hex.hex()

    @staticmethod
    def convert_bytes_pointer_to_int(b):
        """Converts a memory pointer into an integer.

        For example, a pointer to 0x500432 in memory would look like this in
        Windows x64: 32 04 50 00 00 00 00 00
        This function will convert that data, obtained from
        ReadProcessMemory(), i.e.: b'\x32\x04\x50\x00\x00\x00\x00\x00' to:
        5243954 (an int) which == 0x500432. This 0x500432 int can then be used
        as needed.

        Args:
            b (bytes): A bytes object, e.g. b'\x32\x04\x50\x00\x00\x00\x00\x00'
        Returns:
            int: The memory address pointer represented by b.
        """
        new_address = ''
        for byte in b:
            new_address += hex(byte)[2:].zfill(2)
        return int(''.join(reversed(
            [new_address[i:i + 2] for i in range(0, len(new_address), 2)])),
            16)

    @staticmethod
    def convert_float_to_str_hex(f):
        """Convert float to hex string.

        For example, 1.0 returns '0x3f800000'
        """
        return hex(struct.unpack('<I', struct.pack('<f', f))[0])

    @staticmethod
    def convert_double_to_str_hex(f):
        """Convert double to hex string.

        For example, 1.0 returns '0x3ff0000000000000'
        """
        return hex(struct.unpack('<Q', struct.pack('<d', f))[0])

    @staticmethod
    def convert_str_hex_to_str(s, unicode=False, unicode_terminate=True):
        """Convert string containing hex values to a human-readable string.

        For example, '68656c6c6f' converts to 'hello' when unicode is False.
        When unicode is True, '46006C00FC00670065006C00' converts to 'Flügel'.

        Args:
            s (str): The byte string.
            unicode (bool, optional): If True, hexadecimal values in s must be
                separated by '00'.
            unicode_terminate (bool, optional): If True, return as soon as the
                unicode terminating sequence '0000' is encountered.
        Returns:
            str: A human-readable string, no longer in hexadecimal.
        """
        result = ''
        if unicode:
            try:
                for i in range(0, len(s), 4):
                    if unicode_terminate:
                        if s[i:i + 4] == '0000':
                            break
                    result += bytes.fromhex(s[i:i + 4]).decode('utf-16')
            except (UnicodeDecodeError, ValueError):
                pass
        else:
            try:
                for i in range(0, len(s), 2):
                    result += bytes.fromhex(s[i:i + 2]).decode('utf-8')
            except (UnicodeDecodeError, ValueError):
                pass
        if result == '':
            return
        return result

    @staticmethod
    def convert_str_hex_esc_to_str(s):
        """Convert hex escaped string to string.

        For example, '\x90\x90\xeb' converts to '9090EB'.
        """
        return ''.join('%02X' % ord(i) for i in s)

    @staticmethod
    def convert_str_unicode_hex_values_to_str(s):
        """Convert string containing hex values to ASCII.

        For example, '680065006c006c006f00' converts to 'hello'
        """
        s = s.replace('00', '')
        result = ''
        try:
            for i in range(0, len(s), 2):
                result += bytearray.fromhex(s[i:i + 2]).decode()
        except (UnicodeDecodeError, ValueError):
            pass
        if result == '':
            return
        return result

    @staticmethod
    def convert_str_hex_to_float(s):
        """Convert hex string to float.

        For example, '0x3f800000' returns 1.0
        """
        return struct.unpack('!f', bytes.fromhex(s.replace('0x', '')))[0]

    @staticmethod
    def convert_str_hex_to_double(s):
        """Convert hex string to float.

        For example, '0x3ff0000000000000' returns 1.0
        """
        return struct.unpack('!d', bytes.fromhex(s.replace('0x', '')))[0]

    @staticmethod
    def convert_str_to_unicode_str_hex(s):
        """Convert ASCII string to Unicode hex string with null terminator."""
        return binascii.hexlify(
            ('\x00'.join(s) + '\x00\x00').encode()).decode()