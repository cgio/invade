## Release Notes

#### 0.0.6
**Sep. 18, 2018**
* Update method names and args to use "mc" (for machine code) instead of "opcodes"
* Add support for Capstone (https://github.com/aquynh/capstone)
* Add Tool.get_asm() to convert machine code to assembly
* Add partial process name pattern matching to Tool.get_pids_by_process_name()
* Add case_sensitive and contains args to Scout init
* Add Tool.close_handle()
* Add process handle close/cleanup to Target()
* Add Tool.convert_int_pointer_to_str_hex()
* Add is_x64 arg to Tool.get_mc()
* Add Tool.close_handle()
* Add constant X86_MC_INSN_MAX
* Change Tool.get_mc() to @staticmethod
* Rename Tool.get_mc_len() to Tool.get_mc_size()
* Update Tool.get_file_version() for pefile library update
* Fix Tool.is_process_x64() to correctly return False for 32-bit processes
* Remove self.is_x64 from Tool()