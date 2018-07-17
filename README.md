# Invade

![Invade](https://i.imgur.com/nGSXlnr.jpg "Invade")

Invade is a Python 3 toolkit for interacting with the memory of Windows processes. Common uses include penetration testing, demonstrating software vulnerability proof of concepts, software interoperability, malware research, aiding with debugging and reverse engineering, and computer game modifications.

[https://github.com/cgio/invade](https://github.com/cgio/invade)

[https://pypi.org/project/invade](https://pypi.org/project/invade)


**There are four main classes inside main.py:**

* **Me:** Contains information about the operating environment.
* **Scout:** Contains information about active processes.
* **Target:** Contains information about the target process.
* **Tool:** Contains common and miscellaneous methods.

**Common use case overview:**

1. Create an instance of Me and check the operating environment for compatibility.
2. Use Scout to get a list of active processes and the desired PID (process identifier).
3. Instantiate Target using the PID obtained by Scout.
4. Check Target instance properties for information about the target process.
5. Interact with the target process using Tool methods.

Another common use case is Invade's fast (for Python at least) byte pattern search with wildcard support. Operation is similar to [IDA's](https://www.hex-rays.com) "sequence of bytes" search. Use Tool.search_file_pattern() to search through a file on disk.

Tool.memory_read_pointers() is another useful method. With it, you can read through a series of dynamically allocated memory pointers in another process. The method accepts a string containing a start address and relative pointers with common arithmetic operators.

Static methods are frequently used to increase versatility.

**Refer to main.py for additional information and usage instructions.**

## Installation
Python 3.6+ is required

`pip install invade`

Keystone Engine for Python must be installed separately. Use the desired installer under [Python module for Windows - Binaries](http://www.keystone-engine.org/download/).

## Files
Inside /invade:
* **main.py:** Contains all main code and classes
* **winapi.py:** Contains Windows API code
* **version.py:** Contains version information

## Examples
See [invade_keepass](https://github.com/cgio/invade_keepass) for an example of KeePass password extraction.

## Authors
* **Chad Gosselin** - [https://github.com/cgio](https://github.com/cgio)

## Credits
Thanks to authors and contributors of the following projects:
* [Python](https://www.python.org/downloads) for Windows
* [Keystone Engine](https://github.com/keystone-engine/keystone) (used to translate assembly into opcodes; often for injection or comparative purposes)
* [Cuckoo Sandbox](https://github.com/cuckoosandbox/cuckoo) (debug privilege granting code has been adapted)
* [pefile](https://github.com/erocarrera/pefile) (used for gathering information about PE files)

## License
This project is licensed under the MIT License. See [LICENSE.md](LICENSE.md) for details. This project is for educational purposes only. Use at your own risk.