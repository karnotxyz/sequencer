%builtins output range_check poseidon

from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.cairo_builtins import (
    BitwiseBuiltin,
    EcOpBuiltin,
    HashBuiltin,
    KeccakBuiltin,
    ModBuiltin,
    PoseidonBuiltin,
)
from starkware.cairo.common.sha256_state import Sha256ProcessBlock
from starkware.starknet.builtins.segment_arena.segment_arena import SegmentArenaBuiltin
from starkware.starknet.common.new_syscalls import CallContractRequest, CallContractResponse
from starkware.starknet.core.os.builtins import (
    BuiltinPointers,
    NonSelectableBuiltins,
    SelectableBuiltins,
)
from starkware.starknet.core.os.execution.committed_data import (
    COMMITTED_DATA_CONTRACT_ADDRESS,
    COMMITTED_DATA_GET_VALUE_SELECTOR,
    execute_committed_data_call,
)

// Component test: exercises the actual OS committed_data syscall implementation.
// Public output binds root/index/value. This is NOT a Starknet block proof.
func main{output_ptr: felt*, range_check_ptr, poseidon_ptr: PoseidonBuiltin*}() {
    alloc_locals;
    local root;
    local index;
    local response_value;
    local address;
    local selector;
    local gas;
    local use_committed_data;
    %{
        ids.root = int(program_input['root'])
        ids.index = int(program_input['index'])
        ids.response_value = int(program_input['response_value'])
        ids.address = int(program_input.get('address', ids.COMMITTED_DATA_CONTRACT_ADDRESS))
        ids.selector = int(program_input.get('selector', ids.COMMITTED_DATA_GET_VALUE_SELECTOR))
        ids.gas = int(program_input.get('gas', 2000000))
        ids.use_committed_data = int(program_input.get('use_committed_data', True))
    %}
    local calldata: felt* = new (root, index);
    local request: CallContractRequest* = new CallContractRequest(
        contract_address=address,
        selector=selector,
        calldata_start=cast(calldata, felt*),
        calldata_end=cast(calldata, felt*) + 2,
    );
    let (local response_segment) = alloc();
    local retdata: felt* = new (response_value,);
    let response = cast(response_segment + 2, CallContractResponse*);
    assert [response] = CallContractResponse(
        retdata_start=cast(retdata, felt*), retdata_end=cast(retdata, felt*) + 1
    );
    let syscall_ptr = response_segment;
    tempvar builtin_ptrs = new BuiltinPointers(
        selectable=SelectableBuiltins(
            pedersen=cast(0, HashBuiltin*),
            range_check=0,
            ecdsa=0,
            bitwise=cast(0, BitwiseBuiltin*),
            ec_op=cast(0, EcOpBuiltin*),
            poseidon=poseidon_ptr,
            segment_arena=cast(0, SegmentArenaBuiltin*),
            range_check96=cast(0, felt*),
            add_mod=cast(0, ModBuiltin*),
            mul_mod=cast(0, ModBuiltin*),
        ),
        non_selectable=NonSelectableBuiltins(
            keccak=cast(0, KeccakBuiltin*), sha256=cast(0, Sha256ProcessBlock*)
        ),
    );
    with syscall_ptr, builtin_ptrs {
        execute_committed_data_call(
            request=request, remaining_gas=gas, use_committed_data=use_committed_data
        );
    }
    let poseidon_ptr = builtin_ptrs.selectable.poseidon;
    assert [output_ptr] = address;
    assert [output_ptr + 1] = root;
    assert [output_ptr + 2] = index;
    assert [output_ptr + 3] = response_value;
    let output_ptr = output_ptr + 4;
    return ();
}
