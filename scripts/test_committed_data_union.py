"""Exercise Cairo constraints with independent Python hints, including deliberately malicious ones.

Run inside the repository's Cairo 0 virtualenv. This keeps rejection tests independent of the
Rust witness builder: malformed claims must fail in Cairo, even when a hint supplies them.
"""
from pathlib import Path
from collections import defaultdict
import json

from starkware.cairo.common.poseidon_hash import poseidon_hash_many
from starkware.cairo.lang.compiler.cairo_compile import compile_cairo
from starkware.cairo.lang.vm.cairo_runner import get_main_runner
from starkware.cairo.lang.vm.vm_exceptions import VmException

CAIRO_ROOT = Path(__file__).resolve().parents[1] / "crates/apollo_starknet_os_program/src/cairo"
LEAF_DOMAIN = int.from_bytes(b"CD_MPT_LEAF_V1", "big")
BRANCH_DOMAIN = int.from_bytes(b"CD_MPT_BRANCH_V1", "big")


def tree(entries):
    if len(entries) == 1:
        key, value = entries[0]
        return (poseidon_hash_many([LEAF_DOMAIN, key, value]), key, value)
    bit = (entries[0][0] ^ entries[-1][0]).bit_length() - 1
    pivot = next(index for index, (key, _) in enumerate(entries) if key & (1 << bit))
    left, right = tree(entries[:pivot]), tree(entries[pivot:])
    return (poseidon_hash_many([BRANCH_DOMAIN + bit, left[0], right[0]]), bit, left, right)


def union(node, keys, owners=None, slots=None):
    if not keys:
        return [0, node[0]], [], None
    if len(node) == 3:
        index = keys[node[1]]
        return [1, index], [], None if owners is None else owners[index]
    bit, left, right = node[1:]
    left_proof, left_branches, left_owner = union(
        left, {k: i for k, i in keys.items() if not k & (1 << bit)}, owners, slots
    )
    right_proof, right_branches, right_owner = union(
        right, {k: i for k, i in keys.items() if k & (1 << bit)}, owners, slots
    )
    prefix = [2, bit]
    owner = None
    if owners is not None:
        owner = min(value for value in (left_owner, right_owner) if value is not None)
        prefix.append(slots[owner])
        slots[owner] += 1
    return prefix + left_proof + right_proof, [node[0]] + left_branches + right_branches, owner


def main():
    entries = [(key, key + 100) for key in range(16)]
    root = tree(entries)
    code = """%builtins output range_check bitwise poseidon
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.default_dict import default_dict_new
from starkware.cairo.common.dict import DictAccess
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin, PoseidonBuiltin
from starkware.starknet.core.os.execution.committed_data import committed_data_shared_dispatch, committed_data_finalize
func main{output_ptr: felt*, range_check_ptr, bitwise_ptr: BitwiseBuiltin*, poseidon_ptr: PoseidonBuiltin*}() {
    alloc_locals;
    let (local start: DictAccess*) = default_dict_new(0);
    let committed_data_cache = start;
    local keys: felt*;
    %{ ids.keys = segments.gen_arg([0, 1, 0, 8]) %}
    let (local values) = alloc();
    with committed_data_cache {
        let (local gas1, _) = committed_data_shared_dispatch(ROOT, keys, 3, values, 10000000);
        let (local gas2, _) = committed_data_shared_dispatch(ROOT, keys + 2, 2, values + 3, gas1);
        let (local gas3, _) = committed_data_shared_dispatch(ROOT, keys, 3, values + 5, gas2);
    }
    committed_data_finalize(start, committed_data_cache);
    assert values[0] = 100;
    assert values[1] = 101;
    assert values[2] = 100;
    assert values[3] = 100;
    assert values[4] = 108;
    assert values[5] = 100;
    assert [output_ptr] = gas3;
    let output_ptr = output_ptr + 1;
    return ();
}
""".replace(
        "ROOT", str(root[0])
    )
    program = compile_cairo(
        code, prime=2**251 + 17 * 2**192 + 1, cairo_path=[str(CAIRO_ROOT)], debug_info=True
    )
    replacements = {
        "LoadCommittedDataDeferred": "deferred(ids, memory)",
        "LoadCommittedDataRootUnion": "finalize(ids, memory, segments)",
        "StartCommittedDataFinalization": "pass",
        "EndCommittedDataFinalization": "pass",
    }
    for hints in program.hints.values():
        for hint in hints:
            hint.code = replacements.get(hint.code.strip(), hint.code)
    results = []
    for attack in [
        None,
        "value",
        "underclaim",
        "overclaim",
        "owner",
        "slot",
        "key",
        "opaque",
        "trailing",
    ]:
        seen = set()
        calls = 0

        def deferred(ids, memory):
            nonlocal calls
            count = ids.committed_data_cold_count
            keys = [memory[ids.committed_data_cold_keys + index] for index in range(count)]
            _, branches, _ = union(root, dict(zip(keys, range(len(keys)))))
            new = set(branches) - seen
            seen.update(new)
            claim = len(new)
            if calls == 0:
                if attack in ("underclaim", "owner"):
                    claim -= 1
                if attack == "overclaim":
                    claim += 1
            if calls == 1 and attack == "owner":
                claim += 1
            ids.committed_data_branch_count = claim
            for index, key in enumerate(keys):
                memory[ids.committed_data_cold_values + index] = (
                    key + 100 + (1 if attack == "value" else 0)
                )
            calls += 1

        def finalize(ids, memory, segments):
            count = ids.committed_data_leaf_count
            keys = [memory[ids.committed_data_leaves + 3 * index] for index in range(count)]
            owners = [memory[ids.committed_data_leaves + 3 * index + 2] for index in range(count)]
            proof, _, _ = union(root, dict(zip(keys, range(count))), owners, defaultdict(int))
            if attack == "slot":
                proof[2] = 0
            if attack == "key":
                # Replace a requested leaf index with a different, equally well-formed leaf.
                for index in range(len(proof) - 1):
                    if proof[index : index + 2] == [1, 0]:
                        proof[index + 1] = 1
                        break
            if attack == "opaque":
                proof = [0, root[0]]
            if attack == "trailing":
                proof += [0]
            ids.committed_data_proof = segments.gen_arg(proof)
            ids.committed_data_proof_end = ids.committed_data_proof + len(proof)

        try:
            runner = get_main_runner(
                program,
                hint_locals={"deferred": deferred, "finalize": finalize},
                layout="recursive_with_poseidon",
            )
        except VmException as error:
            if attack is None:
                raise
            results.append({"case": attack, "rejected": True, "error": type(error).__name__})
        else:
            assert attack is None, f"Cairo accepted malformed hint: {attack}"
            remaining = runner.vm_memory[runner.builtin_runners["output_builtin"].base]
            # Independent arithmetic for N=(3,2,3), newly read leaves=(2,1,0),
            # and newly expanded branches=(4,3,0). The commitment still hashes twice per node.
            charged = 529138
            assert remaining == 10000000 - charged
            resources = runner.get_execution_resources()
            costs = {
                "range_check_builtin": 70,
                "bitwise_builtin": 583,
                "poseidon_builtin": 491,
                "output_builtin": 0,
            }
            actual = (
                resources.n_steps * 100
                + resources.n_memory_holes * 10
                + sum(
                    costs[name] * count
                    for name, count in resources.builtin_instance_counter.items()
                )
            )
            assert actual <= charged + 3 * (903 * 100 + 18 * 70)
            results.append(
                {
                    "case": "valid_shared_reads",
                    "extra_gas_charged": charged,
                    "complete_wrapper_gas_equivalent": actual,
                    "steps": resources.n_steps,
                }
            )
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
