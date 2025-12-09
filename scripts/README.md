# FLOSS Scripts
FLOSS supports converting its output into scripts for various tools. Please see the render scripts in this directory.
  
Additionally, there is another [plugin for IDA](idaplugin.py) to allow FLOSS to automatically
extract obfuscated strings and apply them to the currently loaded module in IDA. `idaplugin.py` is a IDAPython script you can directly run within IDA Pro (File - Script File... [ALT + F7]).

# Installation
These scripts can be downloaded from the FLOSS [GitHub](https://github.com/mandiant/flare-floss) repository
alongside the source, which is required for the scripts to run.
To install FLOSS as source, see the documentation [here](../doc/installation.md).


# Usage
## Convert FLOSS output for use by other tools

- Run FLOSS on the desired executable with the `-j` or `--json` argument to emit a JSON result
and redirect it to a JSON file.  
    `$ floss -j suspicious.exe > floss_results.json`

For Binary Ninja, IDA Pro, Ghidra or Radare2:
- Run the script for your tool of choice by passing the result json file as an argument and
redirect the output to a Python (.py) file.

Ghidra Example:
    `$ python render-ghidra-import-script.py floss_results.json > apply_floss.py`

- Run the Python script `apply_floss.py` using the desired tool.

Alternatively, you can load FLOSS JSON results directly in Ghidra without the rendering
step by running the `ghidra_floss_import.py` script from Ghidra's Script Manager. The
script will prompt for the JSON file and add comments and bookmarks to the open program.

To build a round-trip workflow, Ghidra analysts can also export decoder hints with
`ghidra_floss_export_hints.py`. Configure the prefixes, bookmark categories, and comment
markers at the top of the script (or use the prompts) to collect addresses to
`force`, `deprioritize`, or `ignore`. The script writes a JSON document containing the
program hash and image base so FLOSS can validate it on import.

`ghidra_floss_import.py` supports a few workflow-friendly options (configured at the top
of the script):

- `IMPORT_DECODED`, `IMPORT_STACK`, `IMPORT_TIGHT`: enable or disable specific string types.
- `MIN_LENGTH`: only import strings whose length meets or exceeds this value.
- `TRUNCATE_LONG_STRINGS`: truncate overly long comments to keep disassembly readable.

When FLOSS metadata contains an image base or hash, the script validates the currently
loaded program, warns on mismatches, and can optionally rebase if the image base differs.
Decoded, stack, and tight strings are placed into separate bookmark categories with
distinct colors, and existing comments are preserved by appending FLOSS annotations.
Decoded strings also annotate both the decoding routine entry point and the callsite when
available.

Pass exported hints back into FLOSS with `--hints-json /path/to/hints.json` (or the
`FLOSS_HINTS_JSON` environment variable). FLOSS validates the hash and image base by
default; use `--ignore-hints-hash-mismatch` if you intentionally want to override that
check. Ignored functions are only removed from emulation when `--enable-hints-ignore` is
provided, keeping the default behavior unchanged when hints are absent.

For x64dbg:
- Instead of a Python file, redirect the output to a .json file.  
    `$ python render-x64dbg-database.py floss-results.json > database.json`

- Open the JSON file `database.json` in x64dbg.
