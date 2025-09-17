#[starknet::contract]
mod starknet_get_storage {
    use hdp_cairo::evm::ETHEREUM_TESTNET_CHAIN_ID;
    use hdp_cairo::{
        HDP,
        evm::storage::{StorageTrait, StorageKey, StorageImpl},
    };

    #[storage]
    struct Storage {}


    #[external(v0)]
    pub fn main(
        ref self: ContractState,
        hdp: HDP,
    ) -> u256 {
        let storage_slot_value_low = hdp
                .evm
                .storage_get_slot(
                    @StorageKey {
                        chain_id: ETHEREUM_TESTNET_CHAIN_ID,
                        block_number: 9080704,
                        address: 0x03C66CB1826BDB0395BF31E68Bf7E873e9564fFB,
                        storage_slot: 0xac997da8d8257fe3025862933200dc3d278d5a173c40c1477d07c590e19daee9,
                    },
        );

        storage_slot_value_low
    }

}