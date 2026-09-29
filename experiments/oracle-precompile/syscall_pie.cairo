%builtins output range_check poseidon

from starkware.cairo.common.sha256_state import Sha256ProcessBlock
from starkware.starknet.builtins.segment_arena.segment_arena import SegmentArenaBuiltin
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.cairo_builtins import (
    PoseidonBuiltin,
    HashBuiltin,
    BitwiseBuiltin,
    EcOpBuiltin,
    ModBuiltin,
    KeccakBuiltin,
)
from starkware.starknet.common.new_syscalls import CallContractRequest, CallContractResponse
from starkware.starknet.core.os.builtins import (
    BuiltinPointers,
    SelectableBuiltins,
    NonSelectableBuiltins,
)
from starkware.starknet.core.os.execution.oracle import (
    execute_oracle_call,
    ORACLE_CONTRACT_ADDRESS,
    ORACLE_GET_PRICE_SELECTOR,
)

// Component test: exercises the actual OS oracle syscall implementation.
// Public output binds root/publisher/asset/price. This is NOT a Starknet block proof.
func main{output_ptr: felt*, range_check_ptr, poseidon_ptr: PoseidonBuiltin*}() {
    alloc_locals;
    local root;
    local publisher;
    local asset;
    local response_price;
    local address;
    local selector;
    local gas;
    %{
        ids.root = int(program_input['root'])
        ids.publisher = int(program_input['publisher'])
        ids.asset = int(program_input['asset'])
        ids.response_price = int(program_input['response_price'])
        ids.address = int(program_input.get('address', ids.ORACLE_CONTRACT_ADDRESS))
        ids.selector = int(program_input.get('selector', ids.ORACLE_GET_PRICE_SELECTOR))
        ids.gas = int(program_input.get('gas', 2000000))
    %}
    local calldata: felt* = new (root, asset);
    local request: CallContractRequest* = new CallContractRequest(
        contract_address=address,
        selector=selector,
        calldata_start=cast(calldata, felt*),
        calldata_end=cast(calldata, felt*) + 2,
    );
    let (local response_segment) = alloc();
    local retdata: felt* = new (response_price,);
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
        execute_oracle_call(request=request, publisher=publisher, remaining_gas=gas);
    }
    let poseidon_ptr = builtin_ptrs.selectable.poseidon;
    assert [output_ptr] = address;
    assert [output_ptr + 1] = root;
    assert [output_ptr + 2] = publisher;
    assert [output_ptr + 3] = asset;
    assert [output_ptr + 4] = response_price;
    let output_ptr = output_ptr + 5;
    return ();
}
