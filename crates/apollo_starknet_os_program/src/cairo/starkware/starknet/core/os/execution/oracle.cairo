// Experimental protocol extension. Not enabled on upstream Starknet.
from starkware.cairo.common.builtin_poseidon.poseidon import poseidon_hash, poseidon_hash_many
from starkware.cairo.common.cairo_builtins import PoseidonBuiltin
from starkware.cairo.common.math import assert_nn, unsigned_div_rem

const ORACLE_CONTRACT_ADDRESS = 5;
const ORACLE_TREE_HEIGHT = 19;
const ORACLE_LEAF_DOMAIN = 'ORACLE_V1';
// Experimental gas charge; must be profiled before production activation.
const ORACLE_READ_GAS = 1000000;

// The publisher is part of the leaf domain: an identical asset in another feed is not interchangeable.
// Root must come from authenticated, current contract state, never just from a witness hint.
func verify_oracle_price{range_check_ptr, poseidon_ptr: PoseidonBuiltin*}(
    root: felt, publisher: felt, asset: felt, price: felt, index: felt, siblings: felt*
) {
    alloc_locals;
    assert_nn(price);
    assert index = asset;
    local leaf_data: felt* = new (ORACLE_LEAF_DOMAIN, publisher, asset, price);
    let (leaf) = poseidon_hash_many(n=4, elements=leaf_data);
    let (calculated_root) = oracle_path(
        node=leaf, index=index, siblings=siblings, remaining=ORACLE_TREE_HEIGHT
    );
    assert calculated_root = root;
    return ();
}

func oracle_path{range_check_ptr, poseidon_ptr: PoseidonBuiltin*}(
    node: felt, index: felt, siblings: felt*, remaining: felt
) -> (root: felt) {
    if (remaining == 0) {
        // Enforces 0 <= original index < 2**ORACLE_TREE_HEIGHT.
        assert index = 0;
        return (root=node);
    }
    let (parent_index, bit) = unsigned_div_rem(index, 2);
    if (bit == 0) {
        let (parent) = poseidon_hash(x=node, y=siblings[0]);
        return oracle_path(parent, parent_index, siblings + 1, remaining - 1);
    }
    let (parent) = poseidon_hash(x=siblings[0], y=node);
    return oracle_path(parent, parent_index, siblings + 1, remaining - 1);
}

// Uses the existing call_contract ABI. The Oracle adapter supplies a root obtained by storage_read.
// Only hints allocate the path; all hashing and the returned price are constrained below.
from starkware.starknet.common.new_syscalls import (
    CallContractRequest,
    CallContractResponse,
    ResponseHeader,
)
from starkware.starknet.core.os.builtins import BuiltinPointers, SelectableBuiltins

const ORACLE_GET_PRICE_SELECTOR = 1108742030766127625244006846509579034896502624161618276319445682010159474408;

func execute_oracle_call{range_check_ptr, syscall_ptr: felt*, builtin_ptrs: BuiltinPointers*}(
    request: CallContractRequest*, publisher: felt, remaining_gas: felt
) {
    alloc_locals;
    assert request.contract_address = ORACLE_CONTRACT_ADDRESS;
    assert request.selector = ORACLE_GET_PRICE_SELECTOR;
    assert request.calldata_end = request.calldata_start + 2;
    local oracle_root = request.calldata_start[0];
    local oracle_asset = request.calldata_start[1];
    local oracle_publisher = publisher;
    local oracle_price;
    local oracle_siblings: felt*;
    %{ LoadOracleWitness %}
    let selectable_builtins = &builtin_ptrs.selectable;
    let poseidon_ptr = selectable_builtins.poseidon;
    with poseidon_ptr {
        verify_oracle_price(
            root=oracle_root,
            publisher=oracle_publisher,
            asset=oracle_asset,
            price=oracle_price,
            index=oracle_asset,
            siblings=oracle_siblings,
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
    assert_nn(remaining_gas - ORACLE_READ_GAS);
    assert [cast(syscall_ptr, ResponseHeader*)] = ResponseHeader(
        gas=remaining_gas - ORACLE_READ_GAS, failure_flag=0
    );
    let response = cast(syscall_ptr + ResponseHeader.SIZE, CallContractResponse*);
    assert response.retdata_end = response.retdata_start + 1;
    assert response.retdata_start[0] = oracle_price;
    let syscall_ptr = syscall_ptr + ResponseHeader.SIZE + CallContractResponse.SIZE;
    return ();
}
