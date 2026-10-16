// Experimental protocol extension. Not enabled on upstream Starknet.
from starkware.cairo.common.builtin_poseidon.poseidon import poseidon_hash_many
from starkware.cairo.common.cairo_builtins import PoseidonBuiltin
from starkware.cairo.common.math import assert_nn, unsigned_div_rem, split_felt

// starknet_keccak("committed_data_v1"), matching the VM/Native protocol reservation.
const COMMITTED_DATA_CONTRACT_ADDRESS = 0x6c5f4559c7041984537bc078c71443fdc58b2e1bab302b341ec12b3d2cec44;
const COMMITTED_DATA_TREE_HEIGHT = 252;
const COMMITTED_DATA_LEAF_DOMAIN = 'CD_MPT_LEAF_V1';
const COMMITTED_DATA_BRANCH_DOMAIN = 'CD_MPT_BRANCH_V1';
from starkware.cairo.common.pow import pow
// The ordinary CallContract entry is already charged. These bounded resources match Blockifier.
const COMMITTED_DATA_STEP_BOUND_BASE = 600;
const COMMITTED_DATA_STEP_BOUND_PER_LEVEL = 400;
const COMMITTED_DATA_CALL_CONTRACT_STEPS = 903;
const COMMITTED_DATA_RANGE_CHECK_BOUND_BASE = 40;
const COMMITTED_DATA_RANGE_CHECK_BOUND_PER_LEVEL = 30;
const COMMITTED_DATA_CALL_CONTRACT_RANGE_CHECKS = 18;
const STEP_SIERRA_GAS = 100;
const RANGE_CHECK_SIERRA_GAS = 70;
const POSEIDON_SIERRA_GAS = 491;

func committed_data_step_charge{range_check_ptr}(height: felt) -> (gas: felt) {
    let bounded_steps = COMMITTED_DATA_STEP_BOUND_BASE + COMMITTED_DATA_STEP_BOUND_PER_LEVEL *
        height;
    let needs_extra = is_le_felt(COMMITTED_DATA_CALL_CONTRACT_STEPS, bounded_steps);
    if (needs_extra == 0) {
        return (gas=0);
    }
    return (gas=(bounded_steps - COMMITTED_DATA_CALL_CONTRACT_STEPS) * STEP_SIERRA_GAS);
}

// Leaves bind the complete felt key. Branches bind their critical bit and both child hashes.
// Root must come from authenticated application state; hints supply evidence only.
func verify_committed_data_value{range_check_ptr, poseidon_ptr: PoseidonBuiltin*}(
    root: felt, key: felt, value: felt, siblings: felt*, height: felt
) {
    alloc_locals;
    local leaf_data: felt* = new (COMMITTED_DATA_LEAF_DOMAIN, key, value);
    let (leaf) = poseidon_hash_many(n=3, elements=leaf_data);
    let (high, low) = split_felt(key);
    let (calculated_root) = committed_data_path(leaf, high, low, siblings, height, -1);
    assert calculated_root = root;
    return ();
}

// unsigned_div_rem bounds its divisor below PRIME / 2**128. Split each 128-bit word
// into 64-bit halves before shifting, so even bit 251 uses a valid divisor.
func committed_data_word_bit{range_check_ptr}(word: felt, bit: felt) -> (direction: felt) {
    alloc_locals;
    let use_lower_half = is_le_felt(bit, 63);
    if (use_lower_half != 0) {
        let (mask) = pow(2, bit);
        let (shifted, _) = unsigned_div_rem(word, mask);
        let (_, direction) = unsigned_div_rem(shifted, 2);
        return (direction=direction);
    }
    let (upper, _) = unsigned_div_rem(word, 2 ** 64);
    let (mask) = pow(2, bit - 64);
    let (shifted, _) = unsigned_div_rem(upper, mask);
    let (_, direction) = unsigned_div_rem(shifted, 2);
    return (direction=direction);
}

func committed_data_key_bit{range_check_ptr}(high: felt, low: felt, bit: felt) -> (
    direction: felt
) {
    let use_low = is_le_felt(bit, 127);
    if (use_low != 0) {
        return committed_data_word_bit(low, bit);
    }
    return committed_data_word_bit(high, bit - 128);
}

func committed_data_path{range_check_ptr, poseidon_ptr: PoseidonBuiltin*}(
    node: felt, high: felt, low: felt, siblings: felt*, remaining: felt, previous_bit: felt
) -> (root: felt) {
    alloc_locals;
    if (remaining == 0) {
        return (root=node);
    }
    local bit = siblings[0];
    // Bound the bit and require canonical bottom-up order; no repeated/reordered branches.
    assert_nn(bit);
    assert_nn(251 - bit);
    assert_nn(bit - previous_bit - 1);
    let (direction) = committed_data_key_bit(high, low, bit);
    if (direction == 0) {
        local data: felt* = new (COMMITTED_DATA_BRANCH_DOMAIN + bit, node, siblings[1]);
        let (parent) = poseidon_hash_many(n=3, elements=data);
        return committed_data_path(parent, high, low, siblings + 2, remaining - 1, bit);
    }
    local data: felt* = new (COMMITTED_DATA_BRANCH_DOMAIN + bit, siblings[1], node);
    let (parent) = poseidon_hash_many(n=3, elements=data);
    return committed_data_path(parent, high, low, siblings + 2, remaining - 1, bit);
}

// Uses the existing call_contract ABI. The CommittedData adapter supplies a root obtained by storage_read.
// Only hints allocate the path; all hashing and the returned value are constrained below.
from starkware.starknet.common.new_syscalls import (
    CallContractRequest,
    CallContractResponse,
    FailureReason,
    ResponseHeader,
)
from starkware.starknet.core.os.builtins import BuiltinPointers, SelectableBuiltins

const COMMITTED_DATA_GET_VALUE_SELECTOR = 1088514629534027837943348492744869453336870381453867699032131389309368223152;

func execute_committed_data_call{
    range_check_ptr, syscall_ptr: felt*, builtin_ptrs: BuiltinPointers*
}(request: CallContractRequest*, remaining_gas: felt, use_committed_data: felt) {
    alloc_locals;
    assert request.contract_address = COMMITTED_DATA_CONTRACT_ADDRESS;
    // Reject this proof instead of making execution depend on a private mode bit.
    assert use_committed_data = 1;
    if (request.selector != COMMITTED_DATA_GET_VALUE_SELECTOR) {
        committed_data_failure(remaining_gas, ERROR_INVALID_ARGUMENT);
        return ();
    }
    if (request.calldata_end != request.calldata_start + 2) {
        committed_data_failure(remaining_gas, ERROR_INVALID_ARGUMENT);
        return ();
    }
    local committed_data_root = request.calldata_start[0];
    local committed_data_key = request.calldata_start[1];
    local committed_data_value;
    local committed_data_siblings: felt*;
    local committed_data_height;
    %{ LoadCommittedDataWitness %}
    let height_valid = is_le_felt(committed_data_height, COMMITTED_DATA_TREE_HEIGHT);
    assert height_valid = 1;
    let (step_charge) = committed_data_step_charge(committed_data_height);
    let range_check_charge = (
        COMMITTED_DATA_RANGE_CHECK_BOUND_BASE +
        COMMITTED_DATA_RANGE_CHECK_BOUND_PER_LEVEL * committed_data_height -
        COMMITTED_DATA_CALL_CONTRACT_RANGE_CHECKS
    ) * RANGE_CHECK_SIERRA_GAS;
    let poseidon_charge = (2 * committed_data_height + 2) * POSEIDON_SIERRA_GAS;
    let committed_data_gas = step_charge + range_check_charge + poseidon_charge;
    let gas_sufficient = is_le_felt(committed_data_gas, remaining_gas);
    if (gas_sufficient == 0) {
        committed_data_failure(remaining_gas, ERROR_OUT_OF_GAS);
        return ();
    }
    let selectable_builtins = &builtin_ptrs.selectable;
    let poseidon_ptr = selectable_builtins.poseidon;
    with poseidon_ptr {
        verify_committed_data_value(
            root=committed_data_root,
            key=committed_data_key,
            value=committed_data_value,
            siblings=committed_data_siblings,
            height=committed_data_height,
        );
    }
    tempvar builtin_ptrs = new BuiltinPointers(
        selectable=SelectableBuiltins(
            pedersen=selectable_builtins.pedersen,
            range_check=selectable_builtins.range_check,
            ecdsa=selectable_builtins.ecdsa,
            bitwise=selectable_builtins.bitwise,
            ec_op=selectable_builtins.ec_op,
            poseidon=poseidon_ptr,
            segment_arena=selectable_builtins.segment_arena,
            range_check96=selectable_builtins.range_check96,
            add_mod=selectable_builtins.add_mod,
            mul_mod=selectable_builtins.mul_mod,
        ),
        non_selectable=builtin_ptrs.non_selectable,
    );
    assert_nn(remaining_gas - committed_data_gas);
    assert [cast(syscall_ptr, ResponseHeader*)] = ResponseHeader(
        gas=remaining_gas - committed_data_gas, failure_flag=0
    );
    let response = cast(syscall_ptr + ResponseHeader.SIZE, CallContractResponse*);
    assert response.retdata_end = response.retdata_start + 1;
    assert response.retdata_start[0] = committed_data_value;
    let syscall_ptr = syscall_ptr + ResponseHeader.SIZE + CallContractResponse.SIZE;
    return ();
}

from starkware.cairo.common.math_cmp import is_le_felt
from starkware.starknet.core.os.constants import ERROR_INVALID_ARGUMENT, ERROR_OUT_OF_GAS

@known_ap_change
func committed_data_failure{syscall_ptr: felt*}(remaining_gas: felt, error: felt) {
    assert [cast(syscall_ptr, ResponseHeader*)] = ResponseHeader(gas=remaining_gas, failure_flag=1);
    let reason = cast(syscall_ptr + ResponseHeader.SIZE, FailureReason*);
    assert reason.end = reason.start + 1;
    assert reason.start[0] = error;
    let syscall_ptr = syscall_ptr + ResponseHeader.SIZE + FailureReason.SIZE;
    return ();
}
