from starkware.cairo.common.cairo_builtins import PoseidonBuiltin, BitwiseBuiltin, KeccakBuiltin
from starkware.cairo.common.dict_access import DictAccess
from starkware.cairo.common.dict import dict_read, dict_write
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.builtin_poseidon.poseidon import poseidon_hash, poseidon_hash_many
from starkware.cairo.common.uint256 import Uint256, uint256_reverse_endian
from starkware.cairo.common.default_dict import default_dict_finalize
from starkware.cairo.common.builtin_keccak.keccak import keccak
from starkware.cairo.common.builtin_keccak.keccak import keccak_bigend

from packages.eth_essentials.lib.mmr import hash_subtree_path, hash_subtree_path_keccak
from src.types import MMRMeta, MMRMetaKeccak, ChainInfo
from src.utils.debug import print_felt_hex, print_string, print_felt

from src.memorizers.evm.memorizer import EvmMemorizer, EvmHashParams
from src.decoders.evm.header_decoder import HeaderDecoder
from src.verifiers.mmr_verifier import validate_mmr_meta_evm, validate_mmr_meta_evm_keccak

func verify_mmr_batches{
    range_check_ptr,
    poseidon_ptr: PoseidonBuiltin*,
    bitwise_ptr: BitwiseBuiltin*,
    keccak_ptr: KeccakBuiltin*,
    pow2_array: felt*,
    evm_memorizer: DictAccess*,
    mmr_metas: MMRMeta*,
    chain_info: ChainInfo,
}(idx: felt, mmr_meta_idx: felt, hashing_fn: felt) -> (mmr_meta_idx: felt) {
    alloc_locals;

    if (0 == idx) {
        return (mmr_meta_idx=mmr_meta_idx);
    }

    %{ vm_enter_scope({'header_with_mmr_evm': batch_evm.headers_with_mmr[ids.idx - 1], '__dict_manager': __dict_manager}) %}
 

    // Dispatch on hashing function
    if (hashing_fn == 0) {
        let (mmr_meta, peaks_dict, peaks_dict_start) = validate_mmr_meta_evm();
        assert mmr_metas[mmr_meta_idx] = mmr_meta;

        tempvar n_header_proofs: felt = nondet %{ len(header_with_mmr_evm.headers) %};
        with mmr_meta, peaks_dict {
            verify_headers_with_mmr_peaks(n_header_proofs);
        }

        // Ensure the peaks dict for this batch is finalized
        default_dict_finalize(peaks_dict_start, peaks_dict, -1);

        %{ vm_exit_scope() %}

        return verify_mmr_batches(idx=idx - 1, mmr_meta_idx=mmr_meta_idx + 1, hashing_fn=hashing_fn);
    } else {
        // Keccak meta verification; run full inclusion verification with Uint256 MMR path and Keccak header hash
        let (mmr_meta_k, peaks_dict_k, peaks_dict_start_k) = validate_mmr_meta_evm_keccak();

        // Convert Keccak Uint256 root to a felt for unified MMRMeta array (Poseidon(low, high))
        let (k_root_felt) = poseidon_hash(mmr_meta_k.root_low, mmr_meta_k.root_high);
        local mmr_meta_conv: MMRMeta = MMRMeta(
            id=mmr_meta_k.id,
            root=k_root_felt,
            size=mmr_meta_k.size,
            chain_id=mmr_meta_k.chain_id,
        );
        assert mmr_metas[mmr_meta_idx] = mmr_meta_conv;

        tempvar n_header_proofs: felt = nondet %{ len(header_with_mmr_evm.headers) %};
        with mmr_meta_k {
            verify_headers_with_mmr_peaks_keccak(n_header_proofs);
        }

        // Finalize dict and exit scope
        default_dict_finalize(peaks_dict_start_k, peaks_dict_k, -1);

        %{ vm_exit_scope() %}

        // Advance mmr_meta_idx for Keccak batches as well (converted root)
        return verify_mmr_batches(idx=idx - 1, mmr_meta_idx=mmr_meta_idx + 1, hashing_fn=hashing_fn);
    }
}

// Guard function that verifies the inclusion of headers in the MMR.
// It ensures:
// 1. The header hash is included in one of the peaks of the MMR.
// 2. The peaks dict contains the computed peak
// The peak checks are performed in isolation, so each MMR batch separately.
// This ensures we dont create a bag of mmr peas from different chains, which are then used to check the header inclusion for every chain
func verify_headers_with_mmr_peaks{
    range_check_ptr,
    poseidon_ptr: PoseidonBuiltin*,
    bitwise_ptr: BitwiseBuiltin*,
    pow2_array: felt*,
    evm_memorizer: DictAccess*,
    chain_info: ChainInfo,
    mmr_meta: MMRMeta,
    peaks_dict: DictAccess*,
}(idx: felt) {
    alloc_locals;
    if (0 == idx) {
        return ();
    }

    let (rlp) = alloc();
    %{
        header_evm = header_with_mmr_evm.headers[ids.idx - 1]
        segments.write_arg(ids.rlp, [int(x, 16) for x in header_evm.rlp])
    %}

    tempvar rlp_len: felt = nondet %{ len(header_evm.rlp) %};
    tempvar leaf_idx: felt = nondet %{ len(header_evm.proof.leaf_idx) %};

    // compute the hash of the header
    let (poseidon_hash) = poseidon_hash_many(n=rlp_len, elements=rlp);
    print_string(470559307697);
    print_felt(leaf_idx);
    print_felt_hex(poseidon_hash);

    // a header can be the right-most peak
    if (leaf_idx == mmr_meta.size) {
        // instead of running an inclusion proof, we ensure its a known peak
        let (contains_peak) = dict_read{dict_ptr=peaks_dict}(poseidon_hash);
        assert contains_peak = 1;

        // add to memorizer
        let block_number = HeaderDecoder.get_block_number(rlp);
        let memorizer_key = EvmHashParams.header(chain_id=chain_info.id, block_number=block_number);
        EvmMemorizer.add(key=memorizer_key, data=rlp);

        return verify_headers_with_mmr_peaks(idx=idx - 1);
    }
    
    // (memorize_headers moved to top-level below)

    let (mmr_path) = alloc();
    tempvar mmr_path_len: felt = nondet %{ len(header_evm.proof.mmr_path) %};
    %{ segments.write_arg(ids.mmr_path, [int(x, 16) for x in header_evm.proof.mmr_path]) %}

    // compute the peak of the header
    let (computed_peak) = hash_subtree_path(
        element=poseidon_hash,
        height=0,
        position=leaf_idx,
        inclusion_proof=mmr_path,
        inclusion_proof_len=mmr_path_len,
    );

        print_string(470559307697);
        print_felt_hex(computed_peak);
     

    // ensure the peak is included in the peaks dict, which contains the peaks of the mmr_root
    let (contains_peak) = dict_read{dict_ptr=peaks_dict}(computed_peak);
    assert contains_peak = 1;

    // add to memorizer
    let block_number = HeaderDecoder.get_block_number(rlp);
    let memorizer_key = EvmHashParams.header(chain_id=chain_info.id, block_number=block_number);
    EvmMemorizer.add(key=memorizer_key, data=rlp);

    return verify_headers_with_mmr_peaks(idx=idx - 1);
}

// Keccak variant: verify inclusion of headers against Keccak-based MMR peaks (Uint256),
// and memorize headers for downstream verifiers.
func verify_headers_with_mmr_peaks_keccak{
    range_check_ptr,
    poseidon_ptr: PoseidonBuiltin*,
    bitwise_ptr: BitwiseBuiltin*,
    keccak_ptr: KeccakBuiltin*,
    pow2_array: felt*,
    evm_memorizer: DictAccess*,
    chain_info: ChainInfo,
    mmr_meta_k: MMRMetaKeccak,
}(idx: felt) {
    alloc_locals;
    if (0 == idx) {
        return ();
    }

    // Recurse first to avoid implicit pointer revocation of bitwise_ptr
    verify_headers_with_mmr_peaks_keccak(idx=idx - 1);
    verify_headers_with_mmr_peaks_keccak_inner(idx, mmr_meta_k);
    return ();

}

// Processes a single header (at position idx) with Keccak-based MMR inclusion.
func verify_headers_with_mmr_peaks_keccak_inner{
    range_check_ptr,
    poseidon_ptr: PoseidonBuiltin*,
    bitwise_ptr: BitwiseBuiltin*,
    keccak_ptr: KeccakBuiltin*,
    pow2_array: felt*,
    evm_memorizer: DictAccess*,
    chain_info: ChainInfo,
}(idx: felt, mmr_meta_k: MMRMetaKeccak) {
    alloc_locals;

    // Prepare RLP words for memorization
    let (rlp) = alloc();
    %{
        header_evm = header_with_mmr_evm.headers[ids.idx - 1]
        segments.write_arg(ids.rlp, [int(x, 16) for x in header_evm.rlp])
    %}

    tempvar rlp_len: felt = nondet %{ len(header_evm.rlp) %};


    // Prepare RLP raw bytes for Keccak hashing
    let (rlp_bytes) = alloc();
    %{
        header_evm = header_with_mmr_evm.headers[ids.idx - 1]
        segments.write_arg(ids.rlp_bytes, header_evm.rlp)
    %}
    tempvar rlp_bytes_len: felt = nondet %{ len(header_evm.rlp) %};
    tempvar leaf_idx: felt = nondet %{ len(header_evm.proof.leaf_idx) %};
    
    print_felt(1234); // Debug marker
    print_felt_hex(rlp_bytes_len);

    // Decode once to avoid implicit pointer revocation across branches
    let block_number = HeaderDecoder.get_block_number(rlp);
 
    print_string(470559307697);
    print_felt_hex(leaf_idx);

    local header_hash: Uint256;

 
    // Compute keccak(header_rlp) and normalize to big-endian Uint256 layout to match peaks encoding
     let (header_hash_raw: Uint256) = keccak(inputs=rlp_bytes, n_bytes=rlp_bytes_len);
    print_felt(5678); // Debug marker for header hash low
    print_felt_hex(header_hash_raw.low);
    let (header_hash: Uint256) = uint256_reverse_endian(header_hash_raw);
    print_felt(9012); // Debug marker for header hash high
    print_felt_hex(header_hash_raw.high);

   // 
  


  //  header_hash.high =0x6fe48f6fcfd9737a9a58b602fa74beb8 ;
 //   header_hash.low = 0x1b079d9c53150588dd769ea31f0341eb   ;

             print_felt_hex(header_hash.high);
         print_felt_hex(header_hash.low);


    // Load MMR peaks (Uint256 serialized as [low, high] felts) for membership check
    //let (peaks_keccak) = alloc();

    let (peaks_keccak: Uint256*) = alloc();


    tempvar peaks_len: felt = nondet %{ len(header_with_mmr_evm.mmr_meta.peaks) %};
    %{ segments.write_arg(ids.peaks_keccak, header_with_mmr_evm.mmr_meta.peaks) %}

        // Compute peak for this header using a unified path call to preserve implicits
        local computed_peak: Uint256;
    
        // Load MMR path siblings as Uint256 list serialized as [low, high] felts
       // let (mmr_path_keccak) = alloc();

        let (mmr_path: Uint256*) = alloc();

        tempvar mmr_path_len: felt = nondet %{ len(header_evm.proof.mmr_path) %};
        %{ segments.write_arg(ids.mmr_path, header_evm.proof.mmr_path) %}
      
        // Choose effective inclusion proof length: 0 for right-most peak, otherwise provided length
        local eff_len: felt;
        if (leaf_idx == mmr_meta_k.size) {
            assert eff_len = 0;
        } else {
            assert eff_len = mmr_path_len;
        } 
      
        // Always call the keccak MMR path hasher; with eff_len=0 it returns the element unchanged
        let (peak_u256: Uint256) = hash_subtree_path_keccak(  
            element=header_hash,
            height=0,
            position=leaf_idx,
            inclusion_proof=mmr_path,
            inclusion_proof_len=eff_len,
        );
        assert computed_peak.low = peak_u256.low;
        assert computed_peak.high = peak_u256.high;

         print_string(470559307697);
         print_felt_hex(computed_peak.low);
    
        print_string(470559307697);
         print_felt_hex(peaks_len);   
        // Ensure the peak is included in the MMR peaks set
        let (contains_peak) = contains_uint256(peaks_keccak, peaks_len, computed_peak);
        assert contains_peak = 1;
 
        // Memorize header RLP
        let memorizer_key = EvmHashParams.header(chain_id=chain_info.id, block_number=block_number);
        EvmMemorizer.add(key=memorizer_key, data=rlp);
    
                // Rebind implicits to avoid revocation at return
                tempvar range_check_ptr = range_check_ptr;
                tempvar bitwise_ptr = bitwise_ptr;
                return ();
}
 // Helper: check if target Uint256 is contained within a serialized array [low, high] as felts
func contains_uint256{}(arr: felt*, len: felt, target: Uint256) -> (res: felt) {
    alloc_locals;
    if (len == 0) {
        return (res=0);
    }

    // Read current element (two felts represent one Uint256: [low, high])
    local cur_low: felt;
    local cur_high: felt;
    assert cur_low = [arr];
    assert cur_high = [arr + 1];

    // Compare in pure Cairo (no hints)
    // Direct order: [low, high]
    let diff_low = cur_low - target.low;
    if (diff_low == 0) {
        let diff_high = cur_high - target.high;
        if (diff_high == 0) {
            return (res=1);
        }
    }
    // Be tolerant to swapped pair ordering (in case of encoding mismatch): [high, low]
    let diff_low_alt = cur_low - target.high;
    if (diff_low_alt == 0) {
        let diff_high_alt = cur_high - target.low;
        if (diff_high_alt == 0) {
            return (res=1);
        }
    }
    // Recurse
    let (rec) = contains_uint256(arr + 2, len - 1, target);
    return (res=rec);
}
 
// Keep-alive helpers to maintain implicit pointers at function boundaries
func __keep_alive_range{range_check_ptr}() {
    return ();
}
func __keep_alive_bitwise{bitwise_ptr: BitwiseBuiltin*}() {
    return ();
}

// Memorize headers helper (used for Keccak MMR path) to ensure downstream verifiers can load headers from EvmMemorizer.
func memorize_headers{
    range_check_ptr,
    poseidon_ptr: PoseidonBuiltin*,
    bitwise_ptr: BitwiseBuiltin*,
    pow2_array: felt*,
    evm_memorizer: DictAccess*,
    chain_info: ChainInfo,
}(idx: felt, n_total: felt) {
    alloc_locals;
    if (0 == idx) {
        return ();
    }

    let (rlp) = alloc();
    %{
        header_evm = header_with_mmr_evm.headers[ids.idx - 1]
        segments.write_arg(ids.rlp, [int(x, 16) for x in header_evm.rlp])
    %}

    // Store header RLP under (chain_id, block_number) for later retrieval
    let block_number = HeaderDecoder.get_block_number(rlp);
    let memorizer_key = EvmHashParams.header(chain_id=chain_info.id, block_number=block_number);
    EvmMemorizer.add(key=memorizer_key, data=rlp);

    // Debug: print first 3 header block_numbers to compare with transactions (avoid '>' operator)
    let n1 = n_total - 1;
    let n2 = n_total - 2;
    if (idx == n_total) {
        tempvar value: felt = block_number;
        %{ print(f"{ids.value}") %}
        tempvar __dbg = 0;
    }
    if (idx == n1) {
        tempvar value: felt = block_number;
        %{ print(f"{ids.value}") %}
        tempvar __dbg = 0;
    }
    if (idx == n2) {
        tempvar value: felt = block_number;
        %{ print(f"{ids.value}") %}
        tempvar __dbg = 0;
    }

    return memorize_headers(idx=idx - 1, n_total=n_total);
}
