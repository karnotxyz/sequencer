// Experimental protocol extension. Not enabled on upstream Starknet.
from starkware.cairo.common.builtin_poseidon.poseidon import poseidon_hash, poseidon_hash_many
from starkware.cairo.common.cairo_builtins import PoseidonBuiltin
from starkware.cairo.common.math import assert_nn, unsigned_div_rem

// starknet_keccak("committed_data_v1"), matching the VM/Native protocol reservation.
const COMMITTED_DATA_CONTRACT_ADDRESS = 0x6c5f4559c7041984537bc078c71443fdc58b2e1bab302b341ec12b3d2cec44;
const COMMITTED_DATA_TREE_HEIGHT = 19;
const COMMITTED_DATA_LEAF_DOMAIN = 'COMMITTED_DATA_V1';
// Experimental gas charge; must be profiled before production activation.
const COMMITTED_DATA_READ_GAS = 1000000;

// The publisher is part of the leaf domain: an identical index in another feed is not interchangeable.
// Root must come from authenticated, current contract state, never just from a witness hint.
func verify_committed_data_value{range_check_ptr, poseidon_ptr: PoseidonBuiltin*}(
    root: felt, publisher: felt, index: felt, value: felt, siblings: felt*
) {
    alloc_locals;
    local leaf_data: felt* = new (COMMITTED_DATA_LEAF_DOMAIN, publisher, index, value);
    let (leaf) = poseidon_hash_many(n=4, elements=leaf_data);
    let (calculated_root) = committed_data_path(
        node=leaf, index=index, siblings=siblings, remaining=COMMITTED_DATA_TREE_HEIGHT
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
    ResponseHeader,
    FailureReason,
)
from starkware.starknet.core.os.builtins import BuiltinPointers, SelectableBuiltins

const COMMITTED_DATA_GET_VALUE_SELECTOR = 1088514629534027837943348492744869453336870381453867699032131389309368223152;

func execute_committed_data_call{range_check_ptr, syscall_ptr: felt*, builtin_ptrs: BuiltinPointers*}(
    request: CallContractRequest*, publisher: felt, remaining_gas: felt
) {
    alloc_locals;
    assert request.contract_address = COMMITTED_DATA_CONTRACT_ADDRESS;
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
    let gas_sufficient = is_le_felt(COMMITTED_DATA_READ_GAS, remaining_gas);
    if (gas_sufficient == 0) {
        committed_data_failure(remaining_gas, ERROR_OUT_OF_GAS);
        return ();
    }
    local committed_data_root = request.calldata_start[0];
    local committed_data_index = request.calldata_start[1];
    local committed_data_publisher = publisher;
    local committed_data_value;
    local committed_data_siblings: felt*;
    %{ LoadCommittedDataWitness %}
    let selectable_builtins = &builtin_ptrs.selectable;
    let poseidon_ptr = selectable_builtins.poseidon;
    with poseidon_ptr {
        verify_committed_data_value(
            root=committed_data_root,
            publisher=committed_data_publisher,
            index=committed_data_index,
            value=committed_data_value,
            siblings=committed_data_siblings,
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
    assert_nn(remaining_gas - COMMITTED_DATA_READ_GAS);
    assert [cast(syscall_ptr, ResponseHeader*)] = ResponseHeader(
        gas=remaining_gas - COMMITTED_DATA_READ_GAS, failure_flag=0
    );
    let response = cast(syscall_ptr + ResponseHeader.SIZE, CallContractResponse*);
    assert response.retdata_end = response.retdata_start + 1;
    assert response.retdata_start[0] = committed_data_value;
    let syscall_ptr = syscall_ptr + ResponseHeader.SIZE + CallContractResponse.SIZE;
    return ();
}

// Activation is part of the OS config hash accepted by settlement, never a free hint flag.
from starkware.cairo.common.math_cmp import is_le_felt
from starkware.starknet.core.os.block_context import BlockContext

@known_ap_change
func committed_data_is_active{range_check_ptr}(block_context: BlockContext*) -> (active: felt) {
    let activation = block_context.os_global_context.starknet_os_config.committed_data_activation;
    let enabled = is_le_felt(1, activation);
    let started = is_le_felt(activation, block_context.block_info_for_execute.block_number + 1);
    return (active=enabled * started);
}

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
