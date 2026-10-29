from starkware.cairo.common.dict import DictAccess, dict_read, dict_write
from starkware.cairo.common.default_dict import default_dict_new, default_dict_finalize
from starkware.starknet.core.os.output import OsCarriedOutputs

// One root owns an append-only dictionary of reads and one branch-count claim per call.
// Finalization authenticates their exact union, preserving the original MPT commitment.
struct CommittedDataRootCache {
    start: DictAccess*,
    end: DictAccess*,
    claims: CommittedDataClaim*,
    calls: felt,
}
// Each expanded branch must occupy one distinct slot charged to its earliest reader.
// Distinct proof addresses prevent a malicious hint from spending the same slot twice.
struct CommittedDataClaim {
    count: felt,
    slots: felt*,
}
// Repeated reads reuse the same value cell and earliest call index.
struct CommittedDataRead {
    value: felt*,
    owner: felt,
}
// Experimental protocol extension. Not enabled on upstream Starknet.
from starkware.cairo.common.poseidon_state import PoseidonBuiltinState
from starkware.cairo.common.cairo_builtins import PoseidonBuiltin, BitwiseBuiltin
from starkware.cairo.common.bitwise import bitwise_and
from starkware.cairo.common.math import assert_nn, unsigned_div_rem, split_felt

// starknet_keccak("committed_data_v1"), matching the VM/Native protocol reservation.
const COMMITTED_DATA_CONTRACT_ADDRESS = 0x6c5f4559c7041984537bc078c71443fdc58b2e1bab302b341ec12b3d2cec44;
const COMMITTED_DATA_TREE_HEIGHT = 252;
const COMMITTED_DATA_LEAF_DOMAIN = 'CD_MPT_LEAF_V1';
const COMMITTED_DATA_BRANCH_DOMAIN = 'CD_MPT_BRANCH_V1';
from starkware.cairo.common.registers import get_label_location
// The ordinary CallContract entry is already charged. These bounded resources match Blockifier.
const COMMITTED_DATA_STEP_BOUND_BASE = 600;
const COMMITTED_DATA_STEP_BOUND_PER_LEVEL = 300;
const COMMITTED_DATA_CALL_CONTRACT_STEPS = 903;
const COMMITTED_DATA_RANGE_CHECK_BOUND_BASE = 40;
const COMMITTED_DATA_RANGE_CHECK_BOUND_PER_LEVEL = 20;
const COMMITTED_DATA_CALL_CONTRACT_RANGE_CHECKS = 18;
const STEP_SIERRA_GAS = 100;
const RANGE_CHECK_SIERRA_GAS = 70;
const POSEIDON_SIERRA_GAS = 491;
const BITWISE_SIERRA_GAS = 583;

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
    let (leaf) = committed_data_hash3(COMMITTED_DATA_LEAF_DOMAIN, key, value);
    let (high, low) = split_felt(key);
    let (calculated_root) = committed_data_path(leaf, high, low, siblings, height, -1);
    assert calculated_root = root;
    return ();
}

// unsigned_div_rem bounds its divisor below PRIME / 2**128. Split each 128-bit word
// into 64-bit halves before shifting, so even bit 251 uses a valid divisor.
func committed_data_word_bit{range_check_ptr}(word: felt, bit: felt) -> (direction: felt) {
    alloc_locals;
    let use_lower_half = is_le(bit, 63);
    if (use_lower_half != 0) {
        let (table) = get_label_location(committed_data_powers);
        let mask = table[bit];
        let (shifted, _) = unsigned_div_rem(word, mask);
        let (_, direction) = unsigned_div_rem(shifted, 2);
        return (direction=direction);
    }
    let (upper, _) = unsigned_div_rem(word, 2 ** 64);
    let (table) = get_label_location(committed_data_powers);
    let mask = table[bit - 64];
    let (shifted, _) = unsigned_div_rem(upper, mask);
    let (_, direction) = unsigned_div_rem(shifted, 2);
    return (direction=direction);
}

func committed_data_key_bit{range_check_ptr}(high: felt, low: felt, bit: felt) -> (
    direction: felt
) {
    let use_low = is_le(bit, 127);
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
        let (parent) = committed_data_hash3(COMMITTED_DATA_BRANCH_DOMAIN + bit, node, siblings[1]);
        return committed_data_path(parent, high, low, siblings + 2, remaining - 1, bit);
    }
    let (parent) = committed_data_hash3(COMMITTED_DATA_BRANCH_DOMAIN + bit, siblings[1], node);
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

const COMMITTED_DATA_GET_VALUES_SELECTOR = 915235083203333064963171029839308968026302113527340519125611694343636180392;
const MAX_COMMITTED_DATA_READ_KEYS = 1024;
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.memcpy import memcpy

// One constrained membership read. Unpaid verification is never a provable syscall result.
func committed_data_read_one{range_check_ptr, poseidon_ptr: PoseidonBuiltin*}(
    committed_data_root: felt, committed_data_key: felt, remaining_gas: felt
) -> (value: felt, gas: felt, error: felt) {
    alloc_locals;
    local committed_data_value;
    local committed_data_siblings: felt*;
    local committed_data_height;
    %{ LoadCommittedDataWitness %}
    let height_valid = is_le_felt(committed_data_height, COMMITTED_DATA_TREE_HEIGHT);
    assert height_valid = 1;
    // Authenticate the hinted height before it can select an out-of-gas result.
    verify_committed_data_value(
        root=committed_data_root,
        key=committed_data_key,
        value=committed_data_value,
        siblings=committed_data_siblings,
        height=committed_data_height,
    );
    let (step_charge) = committed_data_step_charge(committed_data_height);
    let range_check_charge = (
        COMMITTED_DATA_RANGE_CHECK_BOUND_BASE +
        COMMITTED_DATA_RANGE_CHECK_BOUND_PER_LEVEL * committed_data_height -
        COMMITTED_DATA_CALL_CONTRACT_RANGE_CHECKS
    ) * RANGE_CHECK_SIERRA_GAS;
    let poseidon_charge = (2 * committed_data_height + 2) * POSEIDON_SIERRA_GAS;
    local charge = step_charge + range_check_charge + poseidon_charge;
    let gas_sufficient = is_le_felt(charge, remaining_gas);
    // Match the transaction-level Blockifier rejection, even if the caller catches errors.
    with_attr error_message("Insufficient gas for committed-data verification") {
        assert gas_sufficient = 1;
    }
    assert_nn(remaining_gas - charge);
    return (value=committed_data_value, gas=remaining_gas - charge, error=0);
}

// A preorder multiproof expands only the union of requested membership paths. Counts are
// consumed by constrained recursion, not trusted from the hint. Each leaf checks all ancestor
// directions with two 128-bit masks, then hashes its full key/value exactly once.
func committed_data_batch_node{
    range_check_ptr,
    poseidon_ptr: PoseidonBuiltin*,
    bitwise_ptr: BitwiseBuiltin*,
    proof: felt*,
    branches_left,
    leaves_left,
}(
    leaves: felt*,
    leaf_count: felt,
    parent_bit: felt,
    mask_high: felt,
    mask_low: felt,
    path_high: felt,
    path_low: felt,
) -> (hash: felt, used: felt) {
    alloc_locals;
    if (proof[0] == 0) {
        let hash = proof[1];
        let proof = proof + 2;
        return (hash=hash, used=0);
    }
    if (proof[0] == 1) {
        assert_nn(leaves_left - 1);
        let leaves_left = leaves_left - 1;
        let index = proof[1];
        assert_nn(index);
        assert_nn(leaf_count - index - 1);
        local key = leaves[2 * index];
        local value = leaves[2 * index + 1];
        let proof = proof + 2;
        let (local high, local low) = split_felt(key);
        let (actual_high) = bitwise_and(high, mask_high);
        assert actual_high = path_high;
        let (actual_low) = bitwise_and(low, mask_low);
        assert actual_low = path_low;
        let (hash) = committed_data_hash3(COMMITTED_DATA_LEAF_DOMAIN, key, value);
        return (hash=hash, used=1);
    }
    assert proof[0] = 2;
    local bit = proof[1];
    assert_nn(bit);
    assert_nn(parent_bit - bit - 1);
    assert_nn(branches_left - 1);
    let branches_left = branches_left - 1;
    let proof = proof + 2;
    let (local bit_high, local bit_low) = committed_data_mask_bit(bit);
    let (local left, local left_used) = committed_data_batch_node(
        leaves, leaf_count, bit, mask_high + bit_high, mask_low + bit_low, path_high, path_low
    );
    let (right, right_used) = committed_data_batch_node(
        leaves,
        leaf_count,
        bit,
        mask_high + bit_high,
        mask_low + bit_low,
        path_high + bit_high,
        path_low + bit_low,
    );
    local used = left_used + right_used;
    // Every expanded subtree must contain a requested leaf; opaque siblings stay opaque.
    assert_nn(used - 1);
    let (hash) = committed_data_hash3(COMMITTED_DATA_BRANCH_DOMAIN + bit, left, right);
    return (hash=hash, used=used);
}

// Callers constrain bit to 0..251. The table is program data, not hint-controlled memory.
func committed_data_mask_bit{range_check_ptr}(bit: felt) -> (high: felt, low: felt) {
    let use_low = is_le(bit, 127);
    if (use_low != 0) {
        let (table) = get_label_location(committed_data_powers);
        return (high=0, low=table[bit]);
    }
    let (table) = get_label_location(committed_data_powers);
    return (high=table[bit - 128], low=0);
}

// Every requested key is checked against an authenticated leaf. Indices may repeat, so repeated
// requests retain their order without repeating either leaf hashing or membership verification.
func committed_data_batch_values{range_check_ptr}(
    keys: felt*,
    count: felt,
    leaves: felt*,
    leaf_count: felt,
    indices: felt*,
    values: felt*,
    next_leaf: felt,
) {
    if (count == 0) {
        assert next_leaf = leaf_count;
        return ();
    }
    let index = indices[0];
    assert_nn(index);
    assert_nn(leaf_count - index - 1);
    assert leaves[2 * index] = keys[0];
    assert values[0] = leaves[2 * index + 1];
    // First occurrences introduce consecutive leaf indices. Other occurrences may only reuse
    // an already introduced leaf. The terminal equality proves every supplied leaf was requested.
    if (index == next_leaf) {
        return committed_data_batch_values(
            keys + 1, count - 1, leaves, leaf_count, indices + 1, values + 1, next_leaf + 1
        );
    }
    assert_nn(next_leaf - index - 1);
    return committed_data_batch_values(
        keys + 1, count - 1, leaves, leaf_count, indices + 1, values + 1, next_leaf
    );
}

func verify_committed_data_batch{
    range_check_ptr, poseidon_ptr: PoseidonBuiltin*, bitwise_ptr: BitwiseBuiltin*
}(
    root: felt,
    keys: felt*,
    count: felt,
    proof: felt*,
    leaves: felt*,
    indices: felt*,
    branch_count: felt,
    leaf_count: felt,
    values: felt*,
) {
    alloc_locals;
    assert_nn(count - 1);
    assert_nn(MAX_COMMITTED_DATA_READ_KEYS - count);
    assert_nn(branch_count);
    assert_nn(count * COMMITTED_DATA_TREE_HEIGHT - branch_count);
    assert_nn(leaf_count - 1);
    assert_nn(count - leaf_count);
    let branches_left = branch_count;
    let leaves_left = leaf_count;
    with proof, branches_left, leaves_left {
        let (hash, used) = committed_data_batch_node(
            leaves, leaf_count, COMMITTED_DATA_TREE_HEIGHT, 0, 0, 0, 0
        );
        assert used = leaf_count;
        assert hash = root;
        assert branches_left = 0;
        assert leaves_left = 0;
    }
    committed_data_batch_values(keys, count, leaves, leaf_count, indices, values, 0);
    return ();
}

// Counts are verified before the gas comparison: the hint cannot invent a more expensive proof
// to force an out-of-gas response. Insufficient budget rejects the proof instead of returning
// a catchable error with unpaid verification work.
func committed_data_read_batch{
    range_check_ptr, poseidon_ptr: PoseidonBuiltin*, bitwise_ptr: BitwiseBuiltin*
}(
    committed_data_root: felt,
    committed_data_keys: felt*,
    committed_data_count: felt,
    values: felt*,
    remaining_gas: felt,
) -> (gas: felt, error: felt) {
    alloc_locals;
    local committed_data_proof: felt*;
    local committed_data_leaves: felt*;
    local committed_data_indices: felt*;
    local committed_data_branch_count;
    local committed_data_leaf_count;
    %{ LoadCommittedDataBatch %}
    verify_committed_data_batch(
        committed_data_root,
        committed_data_keys,
        committed_data_count,
        committed_data_proof,
        committed_data_leaves,
        committed_data_indices,
        committed_data_branch_count,
        committed_data_leaf_count,
        values,
    );
    // Match Blockifier batch_os_resources, including the output term for duplicate keys.
    let steps = 1000 + 60 * committed_data_count + 160 * committed_data_leaf_count + 160 *
        committed_data_branch_count - COMMITTED_DATA_CALL_CONTRACT_STEPS;
    let range_checks = 30 + 4 * committed_data_count + 12 * committed_data_leaf_count + 6 *
        committed_data_branch_count - COMMITTED_DATA_CALL_CONTRACT_RANGE_CHECKS;
    let poseidons = 2 * (committed_data_branch_count + committed_data_leaf_count);
    let bitwise = 2 * committed_data_leaf_count;
    local charge = steps * STEP_SIERRA_GAS + range_checks * RANGE_CHECK_SIERRA_GAS + poseidons *
        POSEIDON_SIERRA_GAS + bitwise * BITWISE_SIERRA_GAS;
    let gas_sufficient = is_le_felt(charge, remaining_gas);
    with_attr error_message("Insufficient gas for committed-data verification") {
        assert gas_sufficient = 1;
    }
    assert_nn(remaining_gas - charge);
    return (gas=remaining_gas - charge, error=0);
}

// Record requests before reading values. Cold cells are hinted now and authenticated before
// block finalization completes; warm cells are immutable dictionary entries.
func committed_data_collect{leaf_cache: DictAccess*, cold_keys: felt*, cold_values: felt*}(
    keys: felt*, count: felt, references: felt*, owner: felt
) {
    alloc_locals;
    if (count == 0) {
        return ();
    }
    let (cached) = dict_read{dict_ptr=leaf_cache}(key=keys[0]);
    if (cached == 0) {
        assert cold_keys[0] = keys[0];
        assert references[0] = cast(cold_values, felt);
        tempvar read = new CommittedDataRead(value=cold_values, owner=owner);
        dict_write{dict_ptr=leaf_cache}(key=keys[0], new_value=cast(read, felt));
        let cold_keys = cold_keys + 1;
        let cold_values = cold_values + 1;
        return committed_data_collect(keys + 1, count - 1, references + 1, owner);
    }
    let read = cast(cached, CommittedDataRead*);
    assert references[0] = cast(read.value, felt);
    return committed_data_collect(keys + 1, count - 1, references + 1, owner);
}
func committed_data_root_cache{committed_data_cache: DictAccess*}(root: felt) -> (
    start: DictAccess*, end: DictAccess*, claims: CommittedDataClaim*, calls: felt
) {
    alloc_locals;
    let (cached) = dict_read{dict_ptr=committed_data_cache}(key=root);
    if (cached == 0) {
        let (local start) = default_dict_new(0);
        let (claims: CommittedDataClaim*) = alloc();
        return (start=start, end=start, claims=claims, calls=0);
    }
    let certificate = cast(cached, CommittedDataRootCache*);
    return (
        start=certificate.start,
        end=certificate.end,
        claims=certificate.claims,
        calls=certificate.calls,
    );
}
func committed_data_finalize{
    range_check_ptr, bitwise_ptr: BitwiseBuiltin*, poseidon_ptr: PoseidonBuiltin*
}(start: DictAccess*, end: DictAccess*) {
    %{ StartCommittedDataFinalization %}
    let (roots, roots_end) = default_dict_finalize(start, end, 0);
    committed_data_finalize_roots(roots, roots_end);
    %{ EndCommittedDataFinalization %}
    return ();
}
func committed_data_fill_leaves(entries: DictAccess*, count: felt, leaves: felt*) {
    if (count == 0) {
        return ();
    }
    let read = cast(entries.new_value, CommittedDataRead*);
    assert leaves[0] = entries.key;
    assert leaves[1] = [read.value];
    assert leaves[2] = read.owner;
    return committed_data_fill_leaves(entries + DictAccess.SIZE, count - 1, leaves + 3);
}
// Squashing binds the final proof to every actual read, including caught nested reverts.
// No hint may add leaves, omit reads, change returned values, or invent branch charges.
func committed_data_finalize_roots{
    range_check_ptr, bitwise_ptr: BitwiseBuiltin*, poseidon_ptr: PoseidonBuiltin*
}(roots: DictAccess*, roots_end: DictAccess*) {
    alloc_locals;
    if (roots == roots_end) {
        return ();
    }
    local roots_next: DictAccess* = roots + DictAccess.SIZE;
    local roots_end: DictAccess* = roots_end;
    local committed_data_root = roots.key;
    local certificate: CommittedDataRootCache* = cast(roots.new_value, CommittedDataRootCache*);
    let (entries, entries_end) = default_dict_finalize(certificate.start, certificate.end, 0);
    local committed_data_leaf_count = (entries_end - entries) / DictAccess.SIZE;
    assert_nn(committed_data_leaf_count - 1);
    assert_nn(2 ** 64 - committed_data_leaf_count - 1);
    let (local committed_data_leaves: felt*) = alloc();
    committed_data_fill_leaves(entries, committed_data_leaf_count, committed_data_leaves);
    local committed_data_proof: felt*;
    local committed_data_proof_end: felt*;
    %{ LoadCommittedDataRootUnion %}
    local proof_size = committed_data_proof_end - committed_data_proof;
    assert_nn(proof_size);
    assert_nn(2 ** 64 - proof_size - 1);
    let (branches_left) = committed_data_claim_sum(certificate.claims, certificate.calls);
    assert_nn(committed_data_leaf_count * 252 - branches_left);
    let leaves_left = committed_data_leaf_count;
    let proof = committed_data_proof;
    let (masks) = get_label_location(committed_data_powers);
    with proof, branches_left, leaves_left {
        let (hash, owner) = committed_data_union_node(
            masks,
            committed_data_leaves,
            committed_data_leaf_count,
            certificate.claims,
            certificate.calls,
            252,
            0,
            0,
            0,
            0,
        );
        assert hash = committed_data_root;
        assert branches_left = 0;
        assert leaves_left = 0;
        assert proof = committed_data_proof_end;
    }
    return committed_data_finalize_roots(roots_next, roots_end);
}

func committed_data_copy_values(references: felt*, values: felt*, count: felt) {
    if (count == 0) {
        return ();
    }
    assert values[0] = [cast(references[0], felt*)];
    return committed_data_copy_values(references + 1, values + 1, count - 1);
}

func committed_data_shared_dispatch{
    range_check_ptr,
    poseidon_ptr: PoseidonBuiltin*,
    bitwise_ptr: BitwiseBuiltin*,
    committed_data_cache: DictAccess*,
}(root: felt, keys: felt*, count: felt, values: felt*, gas: felt) -> (gas: felt, error: felt) {
    alloc_locals;
    local committed_data_root = root;
    local committed_data_keys: felt* = keys;
    local committed_data_count = count;
    let (local cold_keys_start) = alloc();
    let (local cold_values_start) = alloc();
    let (local references) = alloc();
    let cold_keys = cold_keys_start;
    let cold_values = cold_values_start;
    let (local leaf_start, leaf_end, local claims, local calls) = committed_data_root_cache(root);
    assert_nn(2 ** 64 - calls - 2);
    let leaf_cache = leaf_end;
    with cold_keys, cold_values, leaf_cache {
        committed_data_collect(keys, count, references, calls);
    }
    local cold_count = cold_keys - cold_keys_start;
    local committed_data_cache_start: DictAccess* = leaf_start;
    local committed_data_cold_keys: felt* = cold_keys_start;
    local committed_data_cold_values: felt* = cold_values_start;
    local committed_data_cold_count = cold_count;
    local committed_data_branch_count;
    %{ LoadCommittedDataDeferred %}
    assert_nn(committed_data_branch_count);
    assert_nn(cold_count * 252 - committed_data_branch_count);
    let (slots) = alloc();
    assert [claims + calls * CommittedDataClaim.SIZE] = CommittedDataClaim(
        count=committed_data_branch_count, slots=slots
    );
    tempvar certificate = new CommittedDataRootCache(
        start=leaf_start, end=leaf_cache, claims=claims, calls=calls + 1
    );
    dict_write{dict_ptr=committed_data_cache}(key=root, new_value=cast(certificate, felt));
    local shared_charge = (800 + 80 * count) * STEP_SIERRA_GAS + (20 + 4 * count) *
        RANGE_CHECK_SIERRA_GAS;
    if (cold_count == 0) {
        return committed_data_finish(references, values, count, shared_charge, gas);
    }
    let steps = 1000 + 220 * cold_count + 160 * committed_data_branch_count -
        COMMITTED_DATA_CALL_CONTRACT_STEPS;
    let rc = 30 + 16 * cold_count + 6 * committed_data_branch_count -
        COMMITTED_DATA_CALL_CONTRACT_RANGE_CHECKS;
    let charge = steps * STEP_SIERRA_GAS + rc * RANGE_CHECK_SIERRA_GAS + 2 * (
        committed_data_branch_count + cold_count
    ) * POSEIDON_SIERRA_GAS + 2 * cold_count * BITWISE_SIERRA_GAS;
    return committed_data_finish(references, values, count, shared_charge + charge, gas);
}

func committed_data_finish{
    range_check_ptr,
    poseidon_ptr: PoseidonBuiltin*,
    bitwise_ptr: BitwiseBuiltin*,
    committed_data_cache: DictAccess*,
}(references: felt*, values: felt*, count: felt, charge: felt, gas: felt) -> (
    gas: felt, error: felt
) {
    alloc_locals;
    local range_check_ptr = range_check_ptr;
    local poseidon_ptr: PoseidonBuiltin* = poseidon_ptr;
    local bitwise_ptr: BitwiseBuiltin* = bitwise_ptr;
    local committed_data_cache: DictAccess* = committed_data_cache;
    committed_data_copy_values(references, values, count);
    let (gas, error) = committed_data_charge(charge, gas);
    return (gas=gas, error=error);
}

func committed_data_charge{range_check_ptr}(charge: felt, gas: felt) -> (gas: felt, error: felt) {
    let sufficient = is_le_felt(charge, gas);
    with_attr error_message("Insufficient gas for committed-data verification") {
        assert sufficient = 1;
    }
    assert_nn(gas - charge);
    return (gas=gas - charge, error=0);
}

// Authenticate the union in preorder. Opaque siblings are never expanded; every expanded
// branch inherits the minimum reader index of its descendants and consumes that call's slot.
func committed_data_union_node{
    range_check_ptr,
    bitwise_ptr: BitwiseBuiltin*,
    poseidon_ptr: PoseidonBuiltin*,
    proof: felt*,
    branches_left,
    leaves_left,
}(
    masks: felt*,
    leaves: felt*,
    leaf_count: felt,
    claims: CommittedDataClaim*,
    calls: felt,
    parent_bit: felt,
    mask_high: felt,
    mask_low: felt,
    path_high: felt,
    path_low: felt,
) -> (hash: felt, owner: felt) {
    alloc_locals;
    if (proof[0] == 1) {
        let leaves_left = leaves_left - 1;
        let index = proof[1];
        assert_nn(index);
        assert_nn(leaf_count - index - 1);
        local key = leaves[3 * index];
        local value = leaves[3 * index + 1];
        local owner = leaves[3 * index + 2];
        assert_nn(owner);
        assert_nn(calls - owner - 1);
        let proof = proof + 2;
        let (local high, local low) = split_felt(key);
        let (actual_high) = bitwise_and(high, mask_high);
        assert actual_high = path_high;
        let (actual_low) = bitwise_and(low, mask_low);
        assert actual_low = path_low;
        let (hash) = committed_data_hash3(COMMITTED_DATA_LEAF_DOMAIN, key, value);
        return (hash=hash, owner=owner);
    }
    assert proof[0] = 2;
    local location: felt* = proof;
    local bit = proof[1];
    local slot = proof[2];
    assert_nn(bit);
    assert_nn(parent_bit - bit - 1);
    let branches_left = branches_left - 1;
    let proof = proof + 3;
    local bit_high;
    local bit_low;
    let lower = is_le(bit, 127);
    if (lower != 0) {
        assert bit_high = 0;
        assert bit_low = masks[bit];
    } else {
        assert bit_high = masks[bit - 128];
        assert bit_low = 0;
    }
    if (proof[0] == 0) {
        local left = proof[1];
        let proof = proof + 2;
        let (local right, local owner) = committed_data_union_node(
            masks,
            leaves,
            leaf_count,
            claims,
            calls,
            bit,
            mask_high + bit_high,
            mask_low + bit_low,
            path_high + bit_high,
            path_low + bit_low,
        );
        let claim = claims + owner * CommittedDataClaim.SIZE;
        assert_nn(slot);
        assert_nn(claim.count - slot - 1);
        assert claim.slots[slot] = cast(location, felt);
        let (hash) = committed_data_hash3(COMMITTED_DATA_BRANCH_DOMAIN + bit, left, right);
        return (hash=hash, owner=owner);
    }
    let (local left, local left_owner) = committed_data_union_node(
        masks,
        leaves,
        leaf_count,
        claims,
        calls,
        bit,
        mask_high + bit_high,
        mask_low + bit_low,
        path_high,
        path_low,
    );
    if (proof[0] == 0) {
        local right = proof[1];
        let proof = proof + 2;
        let claim = claims + left_owner * CommittedDataClaim.SIZE;
        assert_nn(slot);
        assert_nn(claim.count - slot - 1);
        assert claim.slots[slot] = cast(location, felt);
        let (hash) = committed_data_hash3(COMMITTED_DATA_BRANCH_DOMAIN + bit, left, right);
        return (hash=hash, owner=left_owner);
    }
    let (local right, right_owner) = committed_data_union_node(
        masks,
        leaves,
        leaf_count,
        claims,
        calls,
        bit,
        mask_high + bit_high,
        mask_low + bit_low,
        path_high + bit_high,
        path_low + bit_low,
    );
    local owner;
    let left_first = is_le(left_owner, right_owner);
    if (left_first != 0) {
        assert owner = left_owner;
    } else {
        assert owner = right_owner;
    }
    let claim = claims + owner * CommittedDataClaim.SIZE;
    assert_nn(slot);
    assert_nn(claim.count - slot - 1);
    assert claim.slots[slot] = cast(location, felt);
    let (hash) = committed_data_hash3(COMMITTED_DATA_BRANCH_DOMAIN + bit, left, right);
    return (hash=hash, owner=owner);
}
func committed_data_claim_sum{range_check_ptr}(claims: CommittedDataClaim*, calls: felt) -> (
    count: felt
) {
    alloc_locals;
    if (calls == 0) {
        return (count=0);
    }
    local count = claims.count;
    assert_nn(count);
    let (rest) = committed_data_claim_sum(claims + CommittedDataClaim.SIZE, calls - 1);
    return (count=count + rest);
}

// Both branches return the same builtin pointers and gas/error shape.
func committed_data_dispatch{
    range_check_ptr,
    poseidon_ptr: PoseidonBuiltin*,
    bitwise_ptr: BitwiseBuiltin*,
    committed_data_cache: DictAccess*,
}(root: felt, keys: felt*, count: felt, values: felt*, gas: felt, batch: felt) -> (
    gas: felt, error: felt
) {
    if (batch != 0) {
        return committed_data_shared_dispatch(root, keys, count, values, gas);
    }
    let (value, gas, error) = committed_data_read_one(root, keys[0], gas);
    assert values[0] = value;
    return (gas=gas, error=error);
}

func execute_committed_data_call{
    range_check_ptr, syscall_ptr: felt*, builtin_ptrs: BuiltinPointers*, outputs: OsCarriedOutputs*
}(request: CallContractRequest*, remaining_gas: felt, use_committed_data: felt) {
    alloc_locals;
    assert request.contract_address = COMMITTED_DATA_CONTRACT_ADDRESS;
    assert use_committed_data = 1;
    local keys: felt*;
    local count;
    local batch;
    local read_range_check_ptr;
    if (request.selector == COMMITTED_DATA_GET_VALUE_SELECTOR) {
        if (request.calldata_end != request.calldata_start + 2) {
            committed_data_failure(remaining_gas, ERROR_INVALID_ARGUMENT);
            return ();
        }
        assert keys = request.calldata_start + 1;
        assert count = 1;
        assert batch = 0;
        assert read_range_check_ptr = range_check_ptr;
    } else {
        if (request.selector != COMMITTED_DATA_GET_VALUES_SELECTOR) {
            committed_data_failure(remaining_gas, ERROR_INVALID_ARGUMENT);
            return ();
        }
        let length = request.calldata_end - request.calldata_start;
        let length_min = is_le_felt(3, length);
        let length_max = is_le_felt(length, MAX_COMMITTED_DATA_READ_KEYS + 2);
        let length_valid = length_min * length_max;
        if (length_valid == 0) {
            committed_data_failure(remaining_gas, ERROR_INVALID_ARGUMENT);
            return ();
        }
        if (request.calldata_start[1] != length - 2) {
            committed_data_failure(remaining_gas, ERROR_INVALID_ARGUMENT);
            return ();
        }
        assert count = length - 2;
        assert keys = request.calldata_start + 2;
        assert batch = 1;
        assert read_range_check_ptr = range_check_ptr;
    }
    let range_check_ptr = read_range_check_ptr;
    let (local values) = alloc();
    let selectable_builtins = &builtin_ptrs.selectable;
    let poseidon_ptr = selectable_builtins.poseidon;
    let bitwise_ptr = selectable_builtins.bitwise;
    let committed_data_cache = outputs.committed_data_cache;
    with poseidon_ptr, bitwise_ptr, committed_data_cache {
        let (local gas, local error) = committed_data_dispatch(
            request.calldata_start[0], keys, count, values, remaining_gas, batch
        );
    }
    tempvar outputs = new OsCarriedOutputs(
        messages_to_l1=outputs.messages_to_l1,
        messages_to_l2=outputs.messages_to_l2,
        committed_data_cache=committed_data_cache,
    );
    tempvar builtin_ptrs = new BuiltinPointers(
        selectable=SelectableBuiltins(
            pedersen=selectable_builtins.pedersen,
            range_check=selectable_builtins.range_check,
            ecdsa=selectable_builtins.ecdsa,
            bitwise=bitwise_ptr,
            ec_op=selectable_builtins.ec_op,
            poseidon=poseidon_ptr,
            segment_arena=selectable_builtins.segment_arena,
            range_check96=selectable_builtins.range_check96,
            add_mod=selectable_builtins.add_mod,
            mul_mod=selectable_builtins.mul_mod,
        ),
        non_selectable=builtin_ptrs.non_selectable,
    );
    if (error != 0) {
        committed_data_failure(gas, error);
        return ();
    }
    assert [cast(syscall_ptr, ResponseHeader*)] = ResponseHeader(gas=gas, failure_flag=0);
    let response = cast(syscall_ptr + ResponseHeader.SIZE, CallContractResponse*);
    assert response.retdata_end = response.retdata_start + count + batch;
    if (batch != 0) {
        assert response.retdata_start[0] = count;
    }
    memcpy(response.retdata_start + batch, values, count);
    let syscall_ptr = syscall_ptr + ResponseHeader.SIZE + CallContractResponse.SIZE;
    return ();
}

from starkware.cairo.common.math_cmp import is_le_felt, is_le
from starkware.starknet.core.os.constants import ERROR_INVALID_ARGUMENT

@known_ap_change
func committed_data_failure{syscall_ptr: felt*}(remaining_gas: felt, error: felt) {
    assert [cast(syscall_ptr, ResponseHeader*)] = ResponseHeader(gas=remaining_gas, failure_flag=1);
    let reason = cast(syscall_ptr + ResponseHeader.SIZE, FailureReason*);
    assert reason.end = reason.start + 1;
    assert reason.start[0] = error;
    let syscall_ptr = syscall_ptr + ResponseHeader.SIZE + FailureReason.SIZE;
    return ();
}

committed_data_powers:
dw 1;
dw 2;
dw 4;
dw 8;
dw 16;
dw 32;
dw 64;
dw 128;
dw 256;
dw 512;
dw 1024;
dw 2048;
dw 4096;
dw 8192;
dw 16384;
dw 32768;
dw 65536;
dw 131072;
dw 262144;
dw 524288;
dw 1048576;
dw 2097152;
dw 4194304;
dw 8388608;
dw 16777216;
dw 33554432;
dw 67108864;
dw 134217728;
dw 268435456;
dw 536870912;
dw 1073741824;
dw 2147483648;
dw 4294967296;
dw 8589934592;
dw 17179869184;
dw 34359738368;
dw 68719476736;
dw 137438953472;
dw 274877906944;
dw 549755813888;
dw 1099511627776;
dw 2199023255552;
dw 4398046511104;
dw 8796093022208;
dw 17592186044416;
dw 35184372088832;
dw 70368744177664;
dw 140737488355328;
dw 281474976710656;
dw 562949953421312;
dw 1125899906842624;
dw 2251799813685248;
dw 4503599627370496;
dw 9007199254740992;
dw 18014398509481984;
dw 36028797018963968;
dw 72057594037927936;
dw 144115188075855872;
dw 288230376151711744;
dw 576460752303423488;
dw 1152921504606846976;
dw 2305843009213693952;
dw 4611686018427387904;
dw 9223372036854775808;
dw 18446744073709551616;
dw 36893488147419103232;
dw 73786976294838206464;
dw 147573952589676412928;
dw 295147905179352825856;
dw 590295810358705651712;
dw 1180591620717411303424;
dw 2361183241434822606848;
dw 4722366482869645213696;
dw 9444732965739290427392;
dw 18889465931478580854784;
dw 37778931862957161709568;
dw 75557863725914323419136;
dw 151115727451828646838272;
dw 302231454903657293676544;
dw 604462909807314587353088;
dw 1208925819614629174706176;
dw 2417851639229258349412352;
dw 4835703278458516698824704;
dw 9671406556917033397649408;
dw 19342813113834066795298816;
dw 38685626227668133590597632;
dw 77371252455336267181195264;
dw 154742504910672534362390528;
dw 309485009821345068724781056;
dw 618970019642690137449562112;
dw 1237940039285380274899124224;
dw 2475880078570760549798248448;
dw 4951760157141521099596496896;
dw 9903520314283042199192993792;
dw 19807040628566084398385987584;
dw 39614081257132168796771975168;
dw 79228162514264337593543950336;
dw 158456325028528675187087900672;
dw 316912650057057350374175801344;
dw 633825300114114700748351602688;
dw 1267650600228229401496703205376;
dw 2535301200456458802993406410752;
dw 5070602400912917605986812821504;
dw 10141204801825835211973625643008;
dw 20282409603651670423947251286016;
dw 40564819207303340847894502572032;
dw 81129638414606681695789005144064;
dw 162259276829213363391578010288128;
dw 324518553658426726783156020576256;
dw 649037107316853453566312041152512;
dw 1298074214633706907132624082305024;
dw 2596148429267413814265248164610048;
dw 5192296858534827628530496329220096;
dw 10384593717069655257060992658440192;
dw 20769187434139310514121985316880384;
dw 41538374868278621028243970633760768;
dw 83076749736557242056487941267521536;
dw 166153499473114484112975882535043072;
dw 332306998946228968225951765070086144;
dw 664613997892457936451903530140172288;
dw 1329227995784915872903807060280344576;
dw 2658455991569831745807614120560689152;
dw 5316911983139663491615228241121378304;
dw 10633823966279326983230456482242756608;
dw 21267647932558653966460912964485513216;
dw 42535295865117307932921825928971026432;
dw 85070591730234615865843651857942052864;
dw 170141183460469231731687303715884105728;

// Same sponge, padding and output as poseidon_hash_many([a, b, c]).
func committed_data_hash3{poseidon_ptr: PoseidonBuiltin*}(a: felt, b: felt, c: felt) -> (
    res: felt
) {
    assert poseidon_ptr.input = PoseidonBuiltinState(s0=a, s1=b, s2=0);
    let state = poseidon_ptr.output;
    let poseidon_ptr = poseidon_ptr + PoseidonBuiltin.SIZE;
    assert poseidon_ptr.input = PoseidonBuiltinState(s0=state.s0 + c, s1=state.s1 + 1, s2=state.s2);
    let res = poseidon_ptr.output.s0;
    let poseidon_ptr = poseidon_ptr + PoseidonBuiltin.SIZE;
    return (res=res);
}
