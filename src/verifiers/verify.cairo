from src.verifiers.evm.verify import run_state_verification as evm_run_state_verification
from src.verifiers.starknet.verify import run_state_verification as starknet_run_state_verification
from starkware.cairo.common.dict_access import DictAccess
from starkware.cairo.common.cairo_builtins import (
    HashBuiltin,
    PoseidonBuiltin,
    BitwiseBuiltin,
    KeccakBuiltin,
    SignatureBuiltin,
    EcOpBuiltin,
)

from src.types import MMRMeta, MMRMetaKeccak, ChainInfo
from src.utils.chain_info import fetch_chain_info, Layout

func run_state_verification{
    range_check_ptr,
    pedersen_ptr: HashBuiltin*,
    poseidon_ptr: PoseidonBuiltin*,
    keccak_ptr: KeccakBuiltin*,
    bitwise_ptr: BitwiseBuiltin*,
    pow2_array: felt*,
    evm_memorizer: DictAccess*,
    starknet_memorizer: DictAccess*,
    mmr_metas: MMRMeta*,
    mmr_metas_keccak: MMRMetaKeccak*,
}() -> (mmr_metas_len_poseidon: felt, mmr_metas_len_keccak: felt) {
    tempvar chain_proofs_len: felt = nondet %{ len(chain_proofs) %};
    let (mmr_meta_idx_poseidon, mmr_meta_idx_keccak, _) = run_state_verification_inner(
        mmr_meta_idx_poseidon=0, mmr_meta_idx_keccak=0, idx=chain_proofs_len
    );
    return (mmr_metas_len_poseidon=mmr_meta_idx_poseidon, mmr_metas_len_keccak=mmr_meta_idx_keccak);
}

func run_state_verification_inner{
    range_check_ptr,
    pedersen_ptr: HashBuiltin*,
    poseidon_ptr: PoseidonBuiltin*,
    keccak_ptr: KeccakBuiltin*,
    bitwise_ptr: BitwiseBuiltin*,
    pow2_array: felt*,
    evm_memorizer: DictAccess*,
    starknet_memorizer: DictAccess*,
    mmr_metas: MMRMeta*,
    mmr_metas_keccak: MMRMetaKeccak*,
}(mmr_meta_idx_poseidon: felt, mmr_meta_idx_keccak: felt, idx: felt) -> (mmr_meta_idx_poseidon: felt, mmr_meta_idx_keccak: felt, idx: felt) {
    alloc_locals;

    if (idx == 0) {
        return (mmr_meta_idx_poseidon=mmr_meta_idx_poseidon, mmr_meta_idx_keccak=mmr_meta_idx_keccak, idx=idx);
    }

    tempvar chain_id: felt = nondet %{ chain_proofs[ids.idx - 1].chain_id %};
    let (local chain_info) = fetch_chain_info(chain_id);

    if (chain_info.layout == Layout.EVM) {
        with chain_info {
            %{ vm_enter_scope({'batch_evm': chain_proofs[ids.idx - 1].value, '__dict_manager': __dict_manager}) %}
            let (mmr_meta_idx_poseidon, mmr_meta_idx_keccak) = evm_run_state_verification(
                mmr_meta_idx_poseidon, mmr_meta_idx_keccak
            );
            %{ vm_exit_scope() %}

            return run_state_verification_inner(
                mmr_meta_idx_poseidon=mmr_meta_idx_poseidon, mmr_meta_idx_keccak=mmr_meta_idx_keccak, idx=idx - 1
            );
        }
    }

    if (chain_info.layout == Layout.STARKNET) {
        with chain_info {
            %{ vm_enter_scope({'batch_starknet': chain_proofs[ids.idx - 1].value, '__dict_manager': __dict_manager}) %}
            let (mmr_meta_idx_poseidon) = starknet_run_state_verification(mmr_meta_idx_poseidon);
            %{ vm_exit_scope() %}

            return run_state_verification_inner(
                mmr_meta_idx_poseidon=mmr_meta_idx_poseidon, mmr_meta_idx_keccak=mmr_meta_idx_keccak, idx=idx - 1
            );
        }
    }

    assert 0 = 1;
    return (mmr_meta_idx_poseidon=0, mmr_meta_idx_keccak=0, idx=0);
}
