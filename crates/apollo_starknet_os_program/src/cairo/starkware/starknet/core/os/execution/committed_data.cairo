// Experimental protocol extension. Not enabled on upstream Starknet.
from starkware.cairo.common.builtin_poseidon.poseidon import poseidon_hash, poseidon_hash_many
from starkware.cairo.common.cairo_builtins import PoseidonBuiltin
from starkware.cairo.common.math import assert_nn, unsigned_div_rem

// starknet_keccak("committed_data_v1"), matching the VM/Native protocol reservation.
const COMMITTED_DATA_CONTRACT_ADDRESS = 0x6c5f4559c7041984537bc078c71443fdc58b2e1bab302b341ec12b3d2cec44;
const COMMITTED_DATA_TREE_HEIGHT = 19;
const COMMITTED_DATA_LEAF_DOMAIN = 'COMMITTED_DATA_V1';
// The ordinary CallContract entry is already charged. These bounded resources match Blockifier.
const COMMITTED_DATA_STEP_BOUND_BASE = 400;
const COMMITTED_DATA_STEP_BOUND_PER_LEVEL = 50;
const COMMITTED_DATA_CALL_CONTRACT_STEPS = 903;
const COMMITTED_DATA_RANGE_CHECK_BOUND_BASE = 20;
const COMMITTED_DATA_RANGE_CHECK_BOUND_PER_LEVEL = 4;
const COMMITTED_DATA_CALL_CONTRACT_RANGE_CHECKS = 18;
const STEP_SIERRA_GAS = 100;
const RANGE_CHECK_SIERRA_GAS = 70;
const POSEIDON_SIERRA_GAS = 491;

func committed_data_step_charge{range_check_ptr}(height: felt) -> (gas: felt) {
    let bounded_steps = COMMITTED_DATA_STEP_BOUND_BASE + COMMITTED_DATA_STEP_BOUND_PER_LEVEL * height;
    let needs_extra = is_le_felt(COMMITTED_DATA_CALL_CONTRACT_STEPS, bounded_steps);
    if (needs_extra == 0) {
        return (gas=0);
    }
    return (gas=(bounded_steps - COMMITTED_DATA_CALL_CONTRACT_STEPS) * STEP_SIERRA_GAS);
}

// Roots bind the indexed values independently of the contract reading them.
// Root must come from authenticated, current contract state, never just from a witness hint.
func verify_committed_data_value{range_check_ptr, poseidon_ptr: PoseidonBuiltin*}(
    root: felt, index: felt, value: felt, siblings: felt*, height: felt
) {
    alloc_locals;
    local leaf_data: felt* = new (COMMITTED_DATA_LEAF_DOMAIN, index, value);
    let (leaf) = poseidon_hash_many(n=3, elements=leaf_data);
    let (calculated_root) = committed_data_path(
        node=leaf, index=index, siblings=siblings, remaining=height
    );
    assert calculated_root = root;
    return ();
}

func committed_data_path{range_check_ptr, poseidon_ptr: PoseidonBuiltin*}(
    node: felt, index: felt, siblings: felt*, remaining: felt
) -> (root: felt) {
    if (remaining == 0) {
        // Enforces 0 <= original index < 2**COMMITTED_DATA_TREE_HEIGHT.
        assert index = 0;
        return (root=node);
    }
    let (parent_index, bit) = unsigned_div_rem(index, 2);
    if (bit == 0) {
        let (parent) = poseidon_hash(x=node, y=siblings[0]);
        return committed_data_path(parent, parent_index, siblings + 1, remaining - 1);
    }
    let (parent) = poseidon_hash(x=siblings[0], y=node);
    return committed_data_path(parent, parent_index, siblings + 1, remaining - 1);
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
    let index_valid = is_le_felt(request.calldata_start[1], 2 ** COMMITTED_DATA_TREE_HEIGHT - 1);
    if (index_valid == 0) {
        committed_data_failure(remaining_gas, ERROR_INVALID_ARGUMENT);
        return ();
    }
    local committed_data_root = request.calldata_start[0];
    local committed_data_index = request.calldata_start[1];
    local committed_data_value;
    local committed_data_siblings: felt*;
    local committed_data_height;
    %{ LoadCommittedDataWitness %}
    let height_valid = is_le_felt(committed_data_height, COMMITTED_DATA_TREE_HEIGHT);
    assert height_valid = 1;
    let (step_charge) = committed_data_step_charge(committed_data_height);
    let range_check_charge = (COMMITTED_DATA_RANGE_CHECK_BOUND_BASE + COMMITTED_DATA_RANGE_CHECK_BOUND_PER_LEVEL * committed_data_height - COMMITTED_DATA_CALL_CONTRACT_RANGE_CHECKS) * RANGE_CHECK_SIERRA_GAS;
    let poseidon_charge = (committed_data_height + 2) * POSEIDON_SIERRA_GAS;
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
            index=committed_data_index,
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
