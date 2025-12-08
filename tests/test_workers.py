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

import pytest

import floss.main
from floss.results import AddressType, DecodedString, StringEncoding


def _fake_worker(args):
    return [
        DecodedString(
            address=function + 0x10,
            address_type=AddressType.GLOBAL,
            string=f"s-{function:x}",
            encoding=StringEncoding.ASCII,
            decoded_at=function + 1,
            decoding_routine=function,
        )
        for function in args.functions
    ]


def _exploding_worker(args):
    raise RuntimeError("boom")


def test_get_worker_count_env(monkeypatch):
    monkeypatch.delenv("FLOSS_WORKERS", raising=False)
    assert floss.main.get_worker_count(None) == 1

    monkeypatch.setenv("FLOSS_WORKERS", "3")
    assert floss.main.get_worker_count(None) == 3

    monkeypatch.setenv("FLOSS_WORKERS", "not-a-number")
    assert floss.main.get_worker_count(None) == 1

    monkeypatch.setenv("FLOSS_WORKERS", "0")
    assert floss.main.get_worker_count(None) == 1


def test_get_worker_count_cli(monkeypatch):
    monkeypatch.setenv("FLOSS_WORKERS", "5")
    assert floss.main.get_worker_count(2) == 2


def test_chunk_functions_distribution():
    functions = list(range(10))
    assert floss.main.chunk_functions(functions, 3) == [
        [0, 1, 2, 3],
        [4, 5, 6, 7],
        [8, 9],
    ]


def test_chunk_functions_single_worker():
    functions = [1, 2, 3]
    assert floss.main.chunk_functions(functions, 1) == [functions]


def test_chunk_functions_empty():
    assert floss.main.chunk_functions([], 4) == []


def test_decode_strings_parallel_matches_single_worker(tmp_path):
    sample_path = tmp_path / "sample.bin"
    sample_path.write_bytes(b"\x00")

    functions = [0x401000, 0x401010, 0x401020]
    order_map = {fva: idx for idx, fva in enumerate(functions)}

    expected = _fake_worker(
        floss.main.DecodeWorkerArgs(
            sample_path=sample_path,
            format="auto",
            sigpaths=[],
            min_length=3,
            functions=functions,
            verbosity=0,
        )
    )

    single_worker = floss.main.decode_strings_parallel(
        sample_path,
        "auto",
        [],
        functions,
        3,
        0,
        worker_count=1,
        function_order=order_map,
        worker_func=_fake_worker,
    )

    multi_worker = floss.main.decode_strings_parallel(
        sample_path,
        "auto",
        [],
        functions,
        3,
        0,
        worker_count=2,
        function_order=order_map,
        worker_func=_fake_worker,
    )

    assert single_worker == expected
    assert multi_worker == expected


def test_decode_strings_parallel_raises_worker_error(tmp_path):
    sample_path = tmp_path / "sample.bin"
    sample_path.write_bytes(b"\x00")

    with pytest.raises(RuntimeError):
        floss.main.decode_strings_parallel(
            sample_path,
            "auto",
            [],
            [0x401000],
            3,
            0,
            worker_count=2,
            function_order={0x401000: 0},
            worker_func=_exploding_worker,
        )
