// Keep the independent batch verifier reachable for adversarial entrypoint tests.
// Production OS dispatch uses shared reads and prunes these standalone helpers.
from starkware.cairo.common.cairo_builtins import PoseidonBuiltin, BitwiseBuiltin
from starkware.starknet.core.os.execution.committed_data import committed_data_read_batch

func read_batch{range_check_ptr, poseidon_ptr: PoseidonBuiltin*, bitwise_ptr: BitwiseBuiltin*}(
    root: felt, keys: felt*, count: felt, values: felt*, gas: felt
) -> (gas: felt, error: felt) {
    return committed_data_read_batch(root, keys, count, values, gas);
}
