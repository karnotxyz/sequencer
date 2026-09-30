#!/usr/bin/env python3
"""Check or regenerate OS hashes with cairo-lang 0.14.1a0 (Python 3.10).

Uses the same source swaps and hash encodings as apollo_starknet_os_program.
Default is read-only. Pass --write only after reviewing a protocol change.
"""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from starkware.cairo.bootloaders.hash_program import HashFunction, compute_program_hash_chain
from starkware.cairo.lang.compiler.program import Program
from starkware.cairo.lang.vm.crypto import pedersen_hash


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    package = repo / 'crates/apollo_starknet_os_program'
    source = package / 'src/cairo'
    compiler = Path(sys.executable).parent / 'cairo-compile'
    results = {}
    with tempfile.TemporaryDirectory(prefix='committed_data-os-hashes-') as tmp:
        virtual = Path(tmp) / 'virtual'
        shutil.copytree(source, virtual)
        for path in virtual.rglob('*__virtual.cairo'):
            shutil.copyfile(path, path.with_name(path.name.replace('__virtual.cairo', '.cairo')))
        for name, root, entry, algorithm in [
            ('os', source, 'starkware/starknet/core/os/os.cairo', HashFunction.PEDERSEN),
            ('virtual_os', virtual, 'starkware/starknet/core/os/os.cairo', HashFunction.BLAKE),
            ('aggregator', source, 'starkware/starknet/core/aggregator/main.cairo', HashFunction.PEDERSEN),
        ]:
            output = Path(tmp) / (name + '.json')
            subprocess.run([str(compiler), str(root / entry), '--debug_info_with_source',
                            '--cairo_path', str(root), '--output', str(output)], check=True)
            program = Program.Schema().loads(output.read_text())
            results[name] = hex(compute_program_hash_chain(
                program, algorithm, encode_blake2s_input=algorithm == HashFunction.BLAKE,
                little_endian_for_blake2s=False))
            print(name, results[name], flush=True)
    results['aggregator_with_prefix'] = hex(pedersen_hash(
        int.from_bytes(b'AGGREGATOR', 'big'), int(results['aggregator'], 16)))
    target = package / 'src/program_hash.json'
    if args.write:
        target.write_text(json.dumps(results, indent=2) + '\n')
    else:
        assert results == json.loads(target.read_text()), 'Compiled program hashes differ'


if __name__ == '__main__':
    main()
