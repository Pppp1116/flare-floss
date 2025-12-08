# Copyright 2017 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import re
from functools import lru_cache
from typing import Iterable
from itertools import chain

from floss.results import StaticString, StringEncoding

# we don't include \r and \n to make output easier to understand by humans and to simplify rendering
ASCII_BYTE = rb" !\"#\$%&\'\(\)\*\+,-\./0123456789:;<=>\?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\[\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}\\\~\t"
ASCII_RE_4 = re.compile(rb"([%s]{%d,})" % (ASCII_BYTE, 4))
UNICODE_RE_4 = re.compile(rb"((?:[%s]\x00){%d,})" % (ASCII_BYTE, 4))
REPEATS = ["A", "\x00", "\xfe", "\xff"]
MIN_LENGTH = 4
SLICE_SIZE = 4096


def buf_filled_with(buf, character):
    if not buf:
        return False

    try:
        mv = memoryview(buf)
    except TypeError:
        mv = None

    if mv is not None:
        if isinstance(character, str):
            char = character.encode("latin1")
        elif isinstance(character, int):
            char = bytes((character,))
        else:
            char = bytes(character[:1]) if hasattr(character, "__getitem__") else bytes(character)

        if not char:
            return False

        dupe_chunk = char * SLICE_SIZE
        for offset in range(0, len(mv), SLICE_SIZE):
            chunk = mv[offset : offset + SLICE_SIZE]
            if len(chunk) == SLICE_SIZE:
                if chunk != dupe_chunk:
                    return False
            elif chunk.tobytes() != dupe_chunk[: len(chunk)]:
                return False
        return True

    dupe_chunk = character * SLICE_SIZE
    for offset in range(0, len(buf), SLICE_SIZE):
        new_chunk = buf[offset : offset + SLICE_SIZE]
        if dupe_chunk[: len(new_chunk)] != new_chunk:
            return False
    return True


def extract_ascii_unicode_strings(buf, n=MIN_LENGTH) -> Iterable[StaticString]:
    yield from chain(extract_ascii_strings(buf, n), extract_unicode_strings(buf, n))


@lru_cache(maxsize=None)
def _ascii_regex(min_length: int) -> re.Pattern:
    if min_length == 4:
        return ASCII_RE_4

    reg = rb"([%s]{%d,})" % (ASCII_BYTE, min_length)
    return re.compile(reg)


@lru_cache(maxsize=None)
def _unicode_regex(min_length: int) -> re.Pattern:
    if min_length == 4:
        return UNICODE_RE_4

    reg = rb"((?:[%s]\x00){%d,})" % (ASCII_BYTE, min_length)
    return re.compile(reg)


def extract_ascii_strings(buf, n=MIN_LENGTH) -> Iterable[StaticString]:
    """
    Extract ASCII strings from the given binary data.

    :param buf: A bytestring.
    :type buf: str
    :param n: The minimum length of strings to extract.
    :type n: int
    :rtype: Sequence[StaticString]
    """

    if not buf:
        return

    if (buf[0] in REPEATS) and buf_filled_with(buf, buf[0]):
        return

    regex = _ascii_regex(n)
    for match in regex.finditer(buf):
        yield StaticString(string=match.group().decode("ascii"), offset=match.start(), encoding=StringEncoding.ASCII)


def extract_unicode_strings(buf, n=MIN_LENGTH) -> Iterable[StaticString]:
    """
    Extract naive UTF-16 strings from the given binary data.

    :param buf: A bytestring.
    :type buf: str
    :param n: The minimum length of strings to extract.
    :type n: int
    :rtype: Sequence[StaticString]
    """

    if not buf:
        return

    if (buf[0] in REPEATS) and buf_filled_with(buf, buf[0]):
        return

    regex = _unicode_regex(n)
    for match in regex.finditer(buf):
        try:
            yield StaticString(
                string=match.group().decode("utf-16"), offset=match.start(), encoding=StringEncoding.UTF16LE
            )
        except UnicodeDecodeError:
            pass


def main():
    import sys

    with open(sys.argv[1], "rb") as f:
        b = f.read()

    for s in extract_ascii_strings(b):
        print("0x{:x}: {:s}".format(s.offset, s.string))

    for s in extract_unicode_strings(b):
        print("0x{:x}: {:s}".format(s.offset, s.string))


if __name__ == "__main__":
    main()
