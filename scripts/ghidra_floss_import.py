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
from java.awt import Color

from ghidra.app.script import GhidraScript
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.symbol import BookmarkType


IMPORT_DECODED = True
IMPORT_STACK = True
IMPORT_TIGHT = True
MIN_LENGTH = 4
TRUNCATE_LONG_STRINGS = 200  # set to 0 or None to disable


COMMENT_TYPE = CodeUnit.EOL_COMMENT
BOOKMARK_TYPES = {
    "FLOSS_Decoded": Color(0, 128, 0),
    "FLOSS_Stack": Color(0, 0, 200),
    "FLOSS_Tight": Color(200, 0, 0),
}


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

        metadata = results.get("metadata", {})
        strings = results.get("strings", {})
        decoded_strings = strings.get("decoded_strings", [])
        stack_strings = strings.get("stack_strings", [])
        tight_strings = strings.get("tight_strings", [])

        self._validate_program(metadata)
        base_offset = self._get_base_offset(metadata)
        self._ensure_bookmark_types()

        total_strings = (
            (len(decoded_strings) if IMPORT_DECODED else 0)
            + (len(stack_strings) if IMPORT_STACK else 0)
            + (len(tight_strings) if IMPORT_TIGHT else 0)
        )
        self.println("Annotating %d strings from FLOSS" % total_strings)
        self.monitor.initialize(total_strings)

        processed = 0

        if IMPORT_DECODED:
            for decoded in decoded_strings:
                self._check_cancelled()
                processed += 1
                self.monitor.incrementProgress(1)
                self.monitor.setMessage("Decoded string %d/%d" % (processed, total_strings))
                self._apply_decoded_string(decoded, base_offset)

        if IMPORT_STACK:
            for stack_string in stack_strings:
                self._check_cancelled()
                processed += 1
                self.monitor.incrementProgress(1)
                self.monitor.setMessage("Stack string %d/%d" % (processed, total_strings))
                self._apply_stack_or_tight(stack_string, "FLOSS_Stack", "stackstring", base_offset)

        if IMPORT_TIGHT:
            for tight_string in tight_strings:
                self._check_cancelled()
                processed += 1
                self.monitor.incrementProgress(1)
                self.monitor.setMessage("Tight string %d/%d" % (processed, total_strings))
                self._apply_stack_or_tight(tight_string, "FLOSS_Tight", "tightstring", base_offset)

        self.println("Finished importing FLOSS results into Ghidra")

    def _apply_decoded_string(self, decoded, base_offset):
        text = decoded.get("string", "")
        if not self._should_import(text):
            return

        comment_text = self._format_comment("decoded string", text)
        decoded_at = decoded.get("decoded_at") or decoded.get("address")
        routine = decoded.get("decoding_routine")

        if decoded_at is not None:
            self._append_comment(decoded_at + base_offset, comment_text, "FLOSS_Decoded")

        if routine is not None:
            routine_comment = self._format_comment("decoding function", text)
            self._append_comment(routine + base_offset, routine_comment, "FLOSS_Decoded")

    def _apply_stack_or_tight(self, item, bookmark_category, label, base_offset):
        text = item.get("string", "")
        if not self._should_import(text):
            return

        address = item.get("program_counter") or item.get("function")
        if address is None:
            return

        comment_text = self._format_comment(label, text)
        self._append_comment(address + base_offset, comment_text, bookmark_category)

    def _append_comment(self, address_int, text, bookmark_category):
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
        self.createBookmark(address, bookmark_category, text)

    def _format_comment(self, label, text):
        if TRUNCATE_LONG_STRINGS and TRUNCATE_LONG_STRINGS > 0 and len(text) > TRUNCATE_LONG_STRINGS:
            text = text[:TRUNCATE_LONG_STRINGS] + "… (truncated)"
        return "FLOSS %s: %s" % (label, text)

    def _should_import(self, text):
        return bool(text) and len(text) >= MIN_LENGTH

    def _check_cancelled(self):
        if self.monitor is not None:
            self.monitor.checkCanceled()

    def _get_base_offset(self, metadata):
        expected_base = metadata.get("imagebase") or metadata.get("image_base")
        if expected_base is None:
            return 0

        current_base = self.currentProgram.getImageBase().getOffset()
        if expected_base == current_base:
            return 0

        offset = current_base - expected_base
        self.println(
            "Image base mismatch: FLOSS 0x%x vs program 0x%x. Applying delta 0x%x." % (
                expected_base,
                current_base,
                offset,
            )
        )

        if self.askYesNo(
            "Rebase program?",
            "FLOSS image base is 0x%x but program is 0x%x. Rebase the program to FLOSS metadata?" % (
                expected_base,
                current_base,
            ),
        ):
            try:
                self.rebaseProgram(self.currentProgram, self.toAddr(expected_base), False)
                self.println("Rebased program to 0x%x" % expected_base)
                return 0
            except Exception as exc:
                self.println("Failed to rebase program: %s" % exc)

        return offset

    def _validate_program(self, metadata):
        floss_hash = metadata.get("sha256") or metadata.get("sha1") or metadata.get("md5")
        if floss_hash:
            program_hash = None
            try:
                program_hash = self.currentProgram.getExecutableSHA256()
            except Exception:
                try:
                    program_hash = self.currentProgram.getExecutableMD5()
                except Exception:
                    program_hash = None

            if program_hash and program_hash.lower() != str(floss_hash).lower():
                self.println(
                    "Warning: Program hash %s does not match FLOSS metadata %s" % (
                        program_hash,
                        floss_hash,
                    )
                )

    def _ensure_bookmark_types(self):
        bookmark_manager = self.currentProgram.getBookmarkManager()
        for category, color in BOOKMARK_TYPES.items():
            try:
                bookmark_type = bookmark_manager.getBookmarkType(category)
                if bookmark_type is None:
                    bookmark_manager.defineType(category, "FLOSS string", None, color)
                elif isinstance(bookmark_type, BookmarkType) and color is not None:
                    bookmark_type.setColor(color)
            except Exception as exc:
                self.println("Could not configure bookmark type %s: %s" % (category, exc))
