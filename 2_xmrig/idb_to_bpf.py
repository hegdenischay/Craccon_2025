#!/usr/bin/env python3
"""
IDB to BPF Script Generator

This standalone tool extracts function information from IDA Pro IDB files
and generates BPFTrace scripts for runtime monitoring and analysis.

Usage:
    python3 idb_to_bpf.py <idb_file> <target_binary> [options]

Options:
    --binary-path PATH      Path to the binary file for ELF analysis
    --max-functions NUM     Maximum number of functions to process (default: 1000)
    --output PATH           Output path for the BPF script (default: auto-generated)
    --include-trivial       Include trivial/library functions in the script
    --verbose               Enable verbose logging

Example:
    python3 idb_to_bpf.py malware.idb malware.exe --binary-path /tmp/malware.exe --max-functions 500
"""

import argparse
import logging
import os
import sys
from pathlib import Path

try:
    import idb
except ImportError:
    print("Error: 'idb' library not found. Install with: pip install python-idb")
    sys.exit(1)

try:
    from elftools.elf.elffile import ELFFile
except ImportError:
    print("Error: 'elftools' library not found. Install with: pip install pyelftools")
    sys.exit(1)


class IDBToBPFGenerator:
    """Standalone IDB to BPF script generator."""

    def __init__(self, max_functions=1000, include_trivial=False, verbose=False):
        self.max_functions = max_functions
        self.include_trivial = include_trivial
        self.verbose = verbose
        self._setup_logging()

    def _setup_logging(self):
        """Setup logging configuration."""
        level = logging.DEBUG if self.verbose else logging.INFO
        logging.basicConfig(level=level, format="%(asctime)s - %(levelname)s - %(message)s")
        self.logger = logging.getLogger(__name__)

    def _check_if_trivial_func(self, func_name):
        """Check if a function is trivial based on its name."""
        if func_name.startswith("main"):
            return False

        # Core system functions
        if func_name in ["_start", "_init", "_libc_start_main", "_libc_start_main_impl"]:
            return True

        # Standard C/C++ library functions
        std_c_prefixes = [
            "std::",
            "__gnu_cxx::",
            "boost::",
            "pthread_",
            "malloc",
            "free",
            "calloc",
            "realloc",
            "printf",
            "scanf",
            "sprintf",
            "fprintf",
            "fopen",
            "fclose",
            "fread",
            "fwrite",
            "memcpy",
            "memset",
            "memcmp",
            "strcpy",
            "strcmp",
            "strlen",
            "strcat",
            "strstr",
            "atoi",
            "atof",
            "exit",
            "abort",
            "signal",
            "setjmp",
            "longjmp",
        ]
        if any(func_name.startswith(prefix) for prefix in std_c_prefixes):
            return True

        # MSVC runtime functions
        msvc_prefixes = [
            "_CRT",
            "_RT",
            "__C_specific_handler",
            "__GSHandlerCheck",
            "__security_check_cookie",
            "_RTC_",
            "_chkstk",
            "_alloca",
            "_invoke_watson",
            "__scrt_",
            "__acrt_",
            "??_",
            "_??",
        ]
        if any(func_name.startswith(prefix) for prefix in msvc_prefixes):
            return True

        # GCC runtime functions
        gcc_prefixes = [
            "__cxa_",
            "__gxx_",
            "__gnu_",
            "_Unwind_",
            "__stack_chk_",
            "__fentry__",
            "_GLOBAL__",
            "__static_initialization_",
            "__throw_",
            "__rethrow_",
        ]
        if any(func_name.startswith(prefix) for prefix in gcc_prefixes):
            return True

        # Windows API and common library functions
        winapi_prefixes = [
            "GetProcAddress",
            "LoadLibrary",
            "FreeLibrary",
            "GetModuleHandle",
            "VirtualAlloc",
            "VirtualFree",
            "CreateFile",
            "ReadFile",
            "WriteFile",
            "CloseHandle",
            "GetLastError",
            "SetLastError",
            "GetCurrentProcess",
            "GetCurrentThread",
            "Sleep",
            "WaitFor",
        ]
        if any(func_name.startswith(prefix) for prefix in winapi_prefixes):
            return True

        # exclude common golang libraries
        common_golang_prefixes = [
            "runtime",
            "reflect",
            "sync",
            "net",
            "os",
            "net_http",
            "vendor",
            "compress",
            "crypto",
            "math",
            "encoding",
            "slices",
            ".",
            "internal",
            "syscall",
            "time",
            "errors",
            "io",
            "unicode",
            "iter",
            "strings",
            "strconv",
            "fmt",
            "path",
            "type__",
        ]
        if any(func_name.startswith(prefix) for prefix in common_golang_prefixes):
            return True

        if func_name.startswith("sub_"):
            return False
        return func_name.startswith("loc_")

    def _get_elf_text_info(self, binary_path):
        """Extract .text section information from ELF binary."""
        if not binary_path or not os.path.exists(binary_path):
            return None, None

        try:
            with open(binary_path, "rb") as f:
                elf = ELFFile(f)
                for section in elf.iter_sections():
                    if section.name == ".text":
                        return section["sh_addr"], section["sh_offset"]
        except Exception as e:
            self.logger.error(f"Error reading ELF file {binary_path}: {e}")

        return None, None

    def _calculate_offset(self, address, text_addr, text_offset):
        """Calculate file offset from virtual address using .text section info."""
        if text_addr is None or text_offset is None:
            return address
        return address - text_addr + text_offset

    def extract_functions_from_idb(self, idb_path):
        """Extract function addresses and names from IDB file."""
        functions = {}

        if not os.path.exists(idb_path):
            self.logger.error(f"IDB file not found: {idb_path}")
            return functions

        try:
            with idb.from_file(idb_path) as db:
                api = idb.IDAPython(db)
                self.logger.info("Extracting functions from IDB...")

                function_count = 0

                for ea in api.idautils.Functions():
                    if function_count >= self.max_functions:
                        self.logger.info(f"Reached maximum function limit ({self.max_functions}), stopping extraction")
                        break

                    function_name = api.idc.GetFunctionName(ea)
                    function_flags = api.idc.GetFunctionFlags(ea)

                    if not function_name:
                        continue

                    is_trivial = self._check_if_trivial_func(function_name)

                    if not self.include_trivial and is_trivial:
                        self.logger.debug(f"Skipping trivial function: {function_name}")
                        continue

                    functions[function_name] = {"address": ea, "flags": function_flags, "is_flirt": not is_trivial}

                    self.logger.debug(f"Function found: {function_name} at 0x{ea:x}")
                    function_count += 1

                self.logger.info(f"Extracted {len(functions)} functions from IDB file")
                return functions

        except Exception as e:
            self.logger.error(f"Error processing IDB file: {e}")
            return {}

    def generate_bpf_script(self, functions, target_binary, binary_path=None):
        """Generate BPFTrace script for monitoring functions."""
        if not target_binary or not functions:
            self.logger.warning("No functions or target binary specified")
            return ""

        # Get .text section information for offset calculation
        text_addr, text_offset = None, None
        if binary_path and os.path.exists(binary_path):
            text_addr, text_offset = self._get_elf_text_info(binary_path)
            if text_addr is not None and text_offset is not None:
                self.logger.info(f"ELF .text section: addr=0x{text_addr:x}, offset=0x{text_offset:x}")
            else:
                self.logger.warning("Could not get .text section info, using raw addresses")

        script_lines = ["#!/usr/bin/env bpftrace", ""]
        script_lines.append(f"// Generated BPF script for {target_binary}")
        script_lines.append(f"// Functions: {len(functions)}")
        script_lines.append(f"// Generated by idb_to_bpf.py")
        script_lines.append("")

        # Add uprobe for each function
        for func_name, func_info in functions.items():
            address = func_info["address"]
            is_flirt = func_info["is_flirt"]
            flirt_tag = "[FLIRT]" if is_flirt else "[USER]"

            # Calculate offset if we have .text section info
            if text_addr is not None and text_offset is not None:
                offset = self._calculate_offset(address, text_addr, text_offset)
                script_lines.append(f"uprobe:{target_binary}:0x{offset:x}")
                self.logger.debug(f"Function {func_name}: address=0x{address:x}, offset=0x{offset:x}")
            else:
                # Fallback to raw address if we can't calculate offset
                script_lines.append(f"uprobe:{target_binary}:0x{address:x}")
                self.logger.debug(f"Function {func_name}: using raw address=0x{address:x}")

            script_lines.append("{")
            script_lines.append(f'    printf("{flirt_tag} Function {func_name} called at %lx by PID %d\\n", arg0, pid);')
            script_lines.append(f'    @function_calls["{func_name}"] = @function_calls["{func_name}"] + 1;')
            script_lines.append("}")
            script_lines.append("")

        # Add interval to print statistics
        script_lines.extend(
            [
                "// Print statistics every 10 seconds",
                "interval:s:10",
                "{",
                "    print(@function_calls);",
                "}",
                "",
                "// Print final statistics on exit",
                "END",
                "{",
                "    print(@function_calls);",
                "    clear(@function_calls);",
                "}",
            ]
        )

        self.logger.info(f"Generated BPF script with {len(functions)} functions")
        return "\n".join(script_lines)

    def save_metadata(self, functions, target_binary, output_path, binary_path=None):
        """Save function metadata to JSON file."""
        import json

        # Get .text section info for metadata
        text_addr, text_offset = None, None
        if binary_path and os.path.exists(binary_path):
            text_addr, text_offset = self._get_elf_text_info(binary_path)

        functions_metadata = {}
        for name, info in functions.items():
            address = info["address"]
            func_data = {"address": hex(address), "is_flirt": info.get("is_flirt", False)}

            # Add offset if we can calculate it
            if text_addr is not None and text_offset is not None:
                offset = self._calculate_offset(address, text_addr, text_offset)
                func_data["offset"] = hex(offset)

            functions_metadata[name] = func_data

        metadata = {
            "functions": functions_metadata,
            "function_count": len(functions),
            "target_binary": target_binary,
            "elf_info": {
                "text_addr": hex(text_addr) if text_addr is not None else None,
                "text_offset": hex(text_offset) if text_offset is not None else None,
            },
        }

        metadata_path = output_path.with_suffix(".json")
        try:
            with open(metadata_path, "w") as f:
                json.dump(metadata, f, indent=2)
            self.logger.info(f"Saved function metadata to {metadata_path}")
        except Exception as e:
            self.logger.warning(f"Failed to save metadata: {e}")


def main():
    """Main function to handle command line arguments and run the generator."""
    parser = argparse.ArgumentParser(
        description="Generate BPFTrace scripts from IDA Pro IDB files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Basic usage
    python3 idb_to_bpf.py malware.idb malware.exe

    # With binary path for ELF analysis
    python3 idb_to_bpf.py malware.idb malware --binary-path /tmp/malware

    # Limit functions and include trivial ones
    python3 idb_to_bpf.py malware.idb malware.exe --max-functions 500 --include-trivial

    # Custom output path with verbose logging
    python3 idb_to_bpf.py malware.idb malware --output /tmp/monitor.bt --verbose
        """,
    )

    parser.add_argument("idb_file", help="Path to the IDA Pro IDB file")
    parser.add_argument("target_binary", help="Name of the target binary to monitor")
    parser.add_argument("--binary-path", help="Path to the binary file for ELF analysis")
    parser.add_argument("--max-functions", type=int, default=100, help="Maximum number of functions to process (default: 1000)")
    parser.add_argument("--output", type=Path, help="Output path for the BPF script (default: auto-generated)")
    parser.add_argument("--include-trivial", action="store_true", help="Include trivial/library functions in the script")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    parser.add_argument("--save-metadata", action="store_true", help="Save function metadata to JSON file")

    args = parser.parse_args()

    # Validate input file
    if not os.path.exists(args.idb_file):
        print(f"Error: IDB file not found: {args.idb_file}")
        sys.exit(1)

    # Generate output path if not specified
    if not args.output:
        idb_name = Path(args.idb_file).stem
        args.output = Path(f"{idb_name}_monitor.bt")

    # Create generator instance
    generator = IDBToBPFGenerator(max_functions=args.max_functions, include_trivial=args.include_trivial, verbose=args.verbose)

    try:
        # Extract functions from IDB
        print(f"Processing IDB file: {args.idb_file}")
        functions = generator.extract_functions_from_idb(args.idb_file)

        if not functions:
            print("No functions extracted from IDB file")
            sys.exit(1)

        print(f"Extracted {len(functions)} functions")

        # Generate BPF script
        print(f"Generating BPF script for target: {args.target_binary}")
        bpf_script = generator.generate_bpf_script(functions, args.target_binary, args.binary_path)

        if not bpf_script:
            print("Failed to generate BPF script")
            sys.exit(1)

        # Save BPF script
        try:
            with open(args.output, "w") as f:
                f.write(bpf_script)
            print(f"BPF script saved to: {args.output}")

            # Make executable
            os.chmod(args.output, 0o755)

        except Exception as e:
            print(f"Error saving BPF script: {e}")
            sys.exit(1)

        # Save metadata if requested
        if args.save_metadata:
            generator.save_metadata(functions, args.target_binary, args.output, args.binary_path)

        print(f"\nSuccess! Generated BPF script with {len(functions)} functions")
        print(f"To run the script: sudo bpftrace {args.output}")

    except KeyboardInterrupt:
        print("\nInterrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        if args.verbose:
            import traceback

            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
