"""
Export FLOSS hint JSON from the current program.

- Functions are selected by name prefix, bookmarks, or comment markers.
- Output JSON includes meta information for FLOSS validation.
- Configure constants below or adjust selections in the UI prompts.
"""

#@category FLOSS

import json
import datetime

from ghidra.app.script import GhidraScript
from ghidra.program.model.listing import CodeUnit

# Configuration. Set PROMPT_FOR_OPTIONS to False to rely only on constants.
FUNCTION_NAME_PREFIXES = ["dec_", "FLOSS_DECODER_"]
BOOKMARK_FORCE_CATEGORIES = ["FLOSS_Decoder_Candidate"]
BOOKMARK_DEPRIORITIZE_CATEGORIES = ["FLOSS_Deprioritize"]
BOOKMARK_IGNORE_CATEGORIES = ["FLOSS_Noise"]
COMMENT_FORCE_MARKERS = ["FLOSS_FORCE"]
COMMENT_DEPRIORITIZE_MARKERS = ["FLOSS_DEPRIORITIZE"]
COMMENT_IGNORE_MARKERS = ["FLOSS_IGNORE"]
PROMPT_FOR_OPTIONS = True
OUTPUT_PATH = None  # when None a save dialog is shown


class FlossExportHints(GhidraScript):
    def run(self):
        output_file = OUTPUT_PATH
        if PROMPT_FOR_OPTIONS or not output_file:
            file_choice = self.askFile("Select output path for FLOSS hints", "Save")
            if file_choice:
                output_file = file_choice.absolutePath
        if not output_file:
            self.println("No output file selected; aborting.")
            return

        force_candidates = set()
        deprioritize_candidates = set()
        ignore_candidates = set()

        function_prefixes = FUNCTION_NAME_PREFIXES
        bookmark_force_categories = BOOKMARK_FORCE_CATEGORIES
        bookmark_deprioritize_categories = BOOKMARK_DEPRIORITIZE_CATEGORIES
        bookmark_ignore_categories = BOOKMARK_IGNORE_CATEGORIES
        comment_force_markers = COMMENT_FORCE_MARKERS
        comment_deprioritize_markers = COMMENT_DEPRIORITIZE_MARKERS
        comment_ignore_markers = COMMENT_IGNORE_MARKERS

        fm = self.currentProgram.getFunctionManager()
        listing = self.currentProgram.getListing()
        total_functions = fm.getFunctionCount()
        self.monitor.initialize(total_functions)

        for idx, func in enumerate(fm.getFunctions(True)):
            self.monitor.checkCanceled()
            self.monitor.setProgress(idx)
            self.monitor.setMessage("Scanning function %s" % func.getName())

            entry = func.getEntryPoint().getOffset()
            name = func.getName() or ""
            if any(name.startswith(prefix) for prefix in function_prefixes):
                force_candidates.add(entry)

            for comment in self._iter_comments(listing, func):
                if any(marker in comment for marker in comment_force_markers):
                    force_candidates.add(entry)
                if any(marker in comment for marker in comment_deprioritize_markers):
                    deprioritize_candidates.add(entry)
                if any(marker in comment for marker in comment_ignore_markers):
                    ignore_candidates.add(entry)

        bookmark_manager = self.currentProgram.getBookmarkManager()
        for category in bookmark_force_categories:
            try:
                iterator = bookmark_manager.getBookmarksIterator(category, None)
            except Exception:
                iterator = []
            for bookmark in iterator:
                self.monitor.checkCanceled()
                force_candidates.add(bookmark.getAddress().getOffset())

        for category in bookmark_deprioritize_categories:
            try:
                iterator = bookmark_manager.getBookmarksIterator(category, None)
            except Exception:
                iterator = []
            for bookmark in iterator:
                self.monitor.checkCanceled()
                deprioritize_candidates.add(bookmark.getAddress().getOffset())

        for category in bookmark_ignore_categories:
            try:
                iterator = bookmark_manager.getBookmarksIterator(category, None)
            except Exception:
                iterator = []
            for bookmark in iterator:
                self.monitor.checkCanceled()
                ignore_candidates.add(bookmark.getAddress().getOffset())

        program_hash = self._get_program_hash()
        imagebase = int(self.currentProgram.getImageBase().getOffset())
        meta = {
            "floss_hints_version": 1,
            "program_hash": program_hash,
            "imagebase": hex(imagebase),
            "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
            "generator": "ghidra_floss_export_hints.py",
        }

        document = {
            "meta": meta,
            "force_candidates": [hex(addr) for addr in sorted(force_candidates)],
            "deprioritize_functions": [hex(addr) for addr in sorted(deprioritize_candidates)],
            "ignore_functions": [hex(addr) for addr in sorted(ignore_candidates)],
        }

        try:
            with open(output_file, "w", encoding="utf-8") as handle:
                json.dump(document, handle, indent=2)
            self.println("Wrote FLOSS hints to %s" % output_file)
        except OSError as exc:
            self.popup("Failed to write hints: %s" % exc)

    def _get_program_hash(self):
        try:
            return self.currentProgram.getExecutableSHA256()
        except Exception:
            try:
                return self.currentProgram.getExecutableMD5()
            except Exception:
                return ""

    def _iter_comments(self, listing, function):
        comments = []
        try:
            cu_iter = listing.getCodeUnits(function.getBody(), True)
            for cu in cu_iter:
                for comment_type in (
                    CodeUnit.EOL_COMMENT,
                    CodeUnit.PRE_COMMENT,
                    CodeUnit.POST_COMMENT,
                    CodeUnit.REPEATABLE_COMMENT,
                    CodeUnit.PLATE_COMMENT,
                ):
                    try:
                        text = cu.getComment(comment_type)
                    except Exception:
                        text = None
                    if text:
                        comments.append(text)
        except Exception:
            return []
        return comments


if __name__ == "__main__":
    script = FlossExportHints()
    script.run()
