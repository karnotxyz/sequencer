// Experimental protocol extension. Not enabled on upstream Starknet.
from starkware.cairo.common.poseidon_state import PoseidonBuiltinState
from starkware.cairo.common.cairo_builtins import PoseidonBuiltin
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
const COMMITTED_DATA_BATCH_STEPS_PER_KEY = 200;
const COMMITTED_DATA_BATCH_RANGE_CHECKS_PER_KEY = 20;
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.memcpy import memcpy

// One constrained membership read. Out-of-gas preserves the gas before this read.
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
    let (step_charge) = committed_data_step_charge(committed_data_height);
    let range_check_charge = (
        COMMITTED_DATA_RANGE_CHECK_BOUND_BASE +
        COMMITTED_DATA_RANGE_CHECK_BOUND_PER_LEVEL * committed_data_height -
        COMMITTED_DATA_CALL_CONTRACT_RANGE_CHECKS
    ) * RANGE_CHECK_SIERRA_GAS;
    let poseidon_charge = (2 * committed_data_height + 2) * POSEIDON_SIERRA_GAS;
    local charge = step_charge + range_check_charge + poseidon_charge;
    let gas_sufficient = is_le_felt(charge, remaining_gas);
    if (gas_sufficient == 0) {
        return (value=0, gas=remaining_gas, error=ERROR_OUT_OF_GAS);
    }
    verify_committed_data_value(
        root=committed_data_root,
        key=committed_data_key,
        value=committed_data_value,
        siblings=committed_data_siblings,
        height=committed_data_height,
    );
    assert_nn(remaining_gas - charge);
    return (value=committed_data_value, gas=remaining_gas - charge, error=0);
}

func committed_data_read_many{range_check_ptr, poseidon_ptr: PoseidonBuiltin*}(
    root: felt, keys: felt*, count: felt, values: felt*, remaining_gas: felt
) -> (gas: felt, error: felt) {
    if (count == 0) {
        return (gas=remaining_gas, error=0);
    }
    let (value, gas, error) = committed_data_read_one(root, keys[0], remaining_gas);
    if (error != 0) {
        return (gas=gas, error=error);
    }
    assert values[0] = value;
    return committed_data_read_many(root, keys + 1, count - 1, values + 1, gas);
}

func execute_committed_data_call{
    range_check_ptr, syscall_ptr: felt*, builtin_ptrs: BuiltinPointers*
}(request: CallContractRequest*, remaining_gas: felt, use_committed_data: felt) {
    alloc_locals;
    assert request.contract_address = COMMITTED_DATA_CONTRACT_ADDRESS;
    assert use_committed_data = 1;
    local keys: felt*;
    local count;
    local batch;
    local read_gas;
    local read_range_check_ptr;
    if (request.selector == COMMITTED_DATA_GET_VALUE_SELECTOR) {
        if (request.calldata_end != request.calldata_start + 2) {
            committed_data_failure(remaining_gas, ERROR_INVALID_ARGUMENT);
            return ();
        }
        assert keys = request.calldata_start + 1;
        assert count = 1;
        assert batch = 0;
        assert read_gas = remaining_gas;
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
        let overhead = (
            (count - 1) * COMMITTED_DATA_CALL_CONTRACT_STEPS +
            count * COMMITTED_DATA_BATCH_STEPS_PER_KEY
        ) * STEP_SIERRA_GAS + (
            (count - 1) * COMMITTED_DATA_CALL_CONTRACT_RANGE_CHECKS +
            count * COMMITTED_DATA_BATCH_RANGE_CHECKS_PER_KEY
        ) * RANGE_CHECK_SIERRA_GAS;
        let gas_sufficient = is_le_felt(overhead, remaining_gas);
        if (gas_sufficient == 0) {
            committed_data_failure(remaining_gas, ERROR_OUT_OF_GAS);
            return ();
        }
        assert read_gas = remaining_gas - overhead;
        assert read_range_check_ptr = range_check_ptr;
    }
    let range_check_ptr = read_range_check_ptr;
    let (local values) = alloc();
    let selectable_builtins = &builtin_ptrs.selectable;
    let poseidon_ptr = selectable_builtins.poseidon;
    with poseidon_ptr {
        let (local gas, local error) = committed_data_read_many(
            request.calldata_start[0], keys, count, values, read_gas
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
