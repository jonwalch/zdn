//! Selected wire types from lightwallet-protocol v0.5.0. See protocol/lightwallet-v0.5.0/README.md.
// Copyright (c) 2019-2021 The Zcash developers. MIT licensed; attribution and license are vendored.
// No build-time protoc or network access is required. Keep field numbers aligned with the pinned schemas.

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Empty {}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ChainSpec {}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BlockId {
    #[prost(uint64, tag = "1")]
    pub height: u64,
    #[prost(bytes = "vec", tag = "2")]
    pub hash: Vec<u8>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BlockRange {
    #[prost(message, optional, tag = "1")]
    pub start: Option<BlockId>,
    #[prost(message, optional, tag = "2")]
    pub end: Option<BlockId>,
    #[prost(int32, repeated, tag = "3")]
    pub pool_types: Vec<i32>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LightdInfo {
    #[prost(string, tag = "1")]
    pub version: String,
    #[prost(string, tag = "2")]
    pub vendor: String,
    #[prost(bool, tag = "3")]
    pub taddr_support: bool,
    #[prost(string, tag = "4")]
    pub chain_name: String,
    #[prost(uint64, tag = "5")]
    pub sapling_activation_height: u64,
    #[prost(string, tag = "6")]
    pub consensus_branch_id: String,
    #[prost(uint64, tag = "7")]
    pub block_height: u64,
    #[prost(string, tag = "8")]
    pub git_commit: String,
    #[prost(string, tag = "9")]
    pub branch: String,
    #[prost(string, tag = "10")]
    pub build_date: String,
    #[prost(string, tag = "11")]
    pub build_user: String,
    #[prost(uint64, tag = "12")]
    pub estimated_height: u64,
    #[prost(string, tag = "13")]
    pub zcashd_build: String,
    #[prost(string, tag = "14")]
    pub zcashd_subversion: String,
    #[prost(string, tag = "15")]
    pub donation_address: String,
    #[prost(string, tag = "16")]
    pub upgrade_name: String,
    #[prost(uint64, tag = "17")]
    pub upgrade_height: u64,
    #[prost(string, tag = "18")]
    pub lightwallet_protocol_version: String,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TreeState {
    #[prost(string, tag = "1")]
    pub network: String,
    #[prost(uint64, tag = "2")]
    pub height: u64,
    #[prost(string, tag = "3")]
    pub hash: String,
    #[prost(uint32, tag = "4")]
    pub time: u32,
    #[prost(string, tag = "5")]
    pub sapling_tree: String,
    #[prost(string, tag = "6")]
    pub orchard_tree: String,
    #[prost(string, tag = "7")]
    pub ironwood_tree: String,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CompactBlock {
    #[prost(uint64, tag = "2")]
    pub height: u64,
    #[prost(bytes = "vec", tag = "3")]
    pub hash: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub prev_hash: Vec<u8>,
    #[prost(uint32, tag = "5")]
    pub time: u32,
    #[prost(bytes = "vec", tag = "6")]
    pub header: Vec<u8>,
    #[prost(message, repeated, tag = "7")]
    pub vtx: Vec<CompactTx>,
    #[prost(message, optional, tag = "8")]
    pub chain_metadata: Option<ChainMetadata>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ChainMetadata {
    #[prost(uint32, tag = "1")]
    pub sapling_commitment_tree_size: u32,
    #[prost(uint32, tag = "2")]
    pub orchard_commitment_tree_size: u32,
    #[prost(uint32, tag = "3")]
    pub ironwood_commitment_tree_size: u32,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CompactTx {
    #[prost(uint64, tag = "1")]
    pub index: u64,
    #[prost(bytes = "vec", tag = "2")]
    pub txid: Vec<u8>,
    #[prost(uint32, tag = "3")]
    pub fee: u32,
    #[prost(message, repeated, tag = "4")]
    pub spends: Vec<CompactSaplingSpend>,
    #[prost(message, repeated, tag = "5")]
    pub outputs: Vec<CompactSaplingOutput>,
    #[prost(message, repeated, tag = "6")]
    pub actions: Vec<CompactOrchardAction>,
    #[prost(message, repeated, tag = "9")]
    pub ironwood_actions: Vec<CompactOrchardAction>,
    #[prost(message, repeated, tag = "7")]
    pub vin: Vec<CompactTxIn>,
    #[prost(message, repeated, tag = "8")]
    pub vout: Vec<TxOut>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CompactSaplingSpend {
    #[prost(bytes = "vec", tag = "1")]
    pub nf: Vec<u8>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CompactSaplingOutput {
    #[prost(bytes = "vec", tag = "1")]
    pub cmu: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub ephemeral_key: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub ciphertext: Vec<u8>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CompactOrchardAction {
    #[prost(bytes = "vec", tag = "1")]
    pub nullifier: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub cmx: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub ephemeral_key: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub ciphertext: Vec<u8>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CompactTxIn {
    #[prost(bytes = "vec", tag = "1")]
    pub prevout_txid: Vec<u8>,
    #[prost(uint32, tag = "2")]
    pub prevout_index: u32,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TxOut {
    #[prost(uint64, tag = "1")]
    pub value: u64,
    #[prost(bytes = "vec", tag = "2")]
    pub script_pub_key: Vec<u8>,
}
