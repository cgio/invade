# Invade

![Invade](https://i.imgur.com/nGSXlnr.jpg "Invade")

Invade is a Python 3 library for interacting with Windows processes. Common uses: software security and malware research, reverse engineering, and PoCs.

[https://github.com/cgio/invade](https://github.com/cgio/invade)

[https://pypi.org/project/invade](https://pypi.org/project/invade)


**There are four classes in main.py:**

* **Me:** for operating environment info
* **Scout:** for process discovery
* **Target:** for target process info
* **Tool:** for main operation

**Common use case overview:**

1. Create an instance of Me and check the operating environment for compatibility.
2. Use Scout to get a list of active processes and the desired PID (process identifier).
3. Instantiate Target using the PID obtained by Scout.
4. Check Target instance properties for information about the target process.
5. Interact with the target process using Tool methods.

Another common use case is Invade's relatively fast byte pattern search with wildcard support. Operation is similar to [IDA's](https://www.hex-rays.com) "sequence of bytes" search. Use Tool.search_file_pattern() to search through a file on disk.

Tool.memory_read_pointers() is also useful. With it, you can read through a series of dynamically allocated memory pointers in another process. The method accepts a string containing a start address and relative pointers with common arithmetic operators.

**Refer to main.py for additional information and usage instructions.**

**Refer to RELEASE.md for release notes.**

## Installation
Python 3.6+ is required

`pip install invade`

Install Keystone for Python. See [Python module for Windows - Binaries](http://www.keystone-engine.org/download/).

Install Capstone for Python. See [Python module for Windows - Binaries](https://www.capstone-engine.org/download.html).

## Files
Inside /invade:
* **main.py:** contains all main code and classes
* **winapi.py:** contains Windows API code
* **version.py:** contains version information

## Example Projects
* [invade_debug_32](https://github.com/cgio/invade_debug_32): Windows x86 32-bit non-attaching debug tool
* [invade_keepass](https://github.com/cgio/invade_keepass): KeePass password exfiltration

## Authors
Chad Gosselin ([https://github.com/cgio](https://github.com/cgio))

## Credits
Thank you to the following projects:

* [Keystone](https://github.com/keystone-engine/keystone): assembler framework
* [Capstone](https://github.com/aquynh/capstone): disassembler framework
* [Cuckoo Sandbox](https://github.com/cuckoosandbox/cuckoo): malware analysis framework
* [pefile](https://github.com/erocarrera/pefile): PE file framework

## License
This project is licensed under the MIT License. See [LICENSE.md](LICENSE.md) for details. This project is for educational purposes only. Use at your own risk.