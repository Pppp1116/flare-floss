"""
Import FLOSS JSON output directly into Ghidra as comments and bookmarks.

Usage (inside Ghidra):
- Run FLOSS with `--json` and save the result to a file.
- In Ghidra's Script Manager, add this repository path and run
  `ghidra_floss_import.py`.
- You will be prompted to select the FLOSS JSON file; comments and bookmarks
  will be applied to the current program.
"""

#@category FLOSS

import json

from ghidra.app.script import GhidraScript
from ghidra.program.model.listing import CodeUnit


COMMENT_TYPE = CodeUnit.EOL_COMMENT


class FlossImportScript(GhidraScript):
    def run(self):
        floss_file = self.askFile("Select FLOSS JSON output", "Open")
        if floss_file is None:
            self.println("No FLOSS results selected; exiting.")
            return

        try:
            with open(floss_file.absolutePath, "r") as handle:
                results = json.load(handle)
        except (IOError, ValueError) as exc:
            self.println("Failed to read FLOSS results: %s" % exc)
            return

        strings = results.get("strings", {})
        decoded_strings = strings.get("decoded_strings", [])
        stack_strings = strings.get("stack_strings", [])
        tight_strings = strings.get("tight_strings", [])

        total_strings = (
            len(decoded_strings) + len(stack_strings) + len(tight_strings)
        )
        self.println("Annotating %d strings from FLOSS" % total_strings)

        for decoded in decoded_strings:
            text = decoded.get("string", "")
            if not text:
                continue

            address = decoded.get("decoded_at") or decoded.get("address")
            if address is None:
                continue

            comment = "FLOSS: %s" % text
            self._append_comment(address, comment, "decoded_string")

        for stack_string in stack_strings:
            text = stack_string.get("string", "")
            if not text:
                continue

            address = stack_string.get("program_counter") or stack_string.get("function")
            if address is None:
                continue

            comment = "FLOSS stackstring: %s" % text
            self._append_comment(address, comment, "stackstring")

        for tight_string in tight_strings:
            text = tight_string.get("string", "")
            if not text:
                continue

            address = tight_string.get("program_counter") or tight_string.get("function")
            if address is None:
                continue

            comment = "FLOSS tightstring: %s" % text
            self._append_comment(address, comment, "tightstring")

        self.println("Finished importing FLOSS results into Ghidra")

    def _append_comment(self, address_int, text, bookmark_type):
        try:
            address = self.toAddr(long(address_int))  # type: ignore[name-defined]
        except Exception:
            self.println("Skipping invalid address: %s" % address_int)
            return

        code_unit = self.currentProgram.getListing().getCodeUnitAt(address)
        if code_unit is None:
            self.println("No code unit at address 0x%x" % int(address_int))
            return

        existing = code_unit.getComment(COMMENT_TYPE)
        if existing and text in existing:
            return

        updated = text if not existing else existing + "\n" + text
        code_unit.setComment(COMMENT_TYPE, updated)
        self.createBookmark(address, bookmark_type, text)
