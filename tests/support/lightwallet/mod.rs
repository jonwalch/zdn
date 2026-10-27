use prost::Message;
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use zdn::{
    chain::{
        manifest::ConsensusManifest,
        rpc::{Clock, NodeRpc, RpcError},
    },
    lightwallet::{wire, LightwalletError, LightwalletRpc},
};

pub fn manifest() -> ConsensusManifest {
    let mut manifest: ConsensusManifest =
        serde_json::from_str(include_str!("../../fixtures/chain-manifest/valid.json")).unwrap();
    manifest.genesis.hash = hash(0);
    manifest
}
pub fn hash(height: u32) -> String {
    hex::encode((0..32).map(|n| (n + height + 1) as u8).collect::<Vec<_>>())
}
pub fn wire_hash(height: u32) -> Vec<u8> {
    let mut bytes = hex::decode(hash(height)).unwrap();
    bytes.reverse();
    bytes
}
pub fn rules() -> Value {
    json!({"apiVersion":"zakura-chain-rules/v1","ruleset":"zakura-configured-testnet/v1","networkKind":"custom-testnet","rules":{
        "networkMagic":"a1b2c3d4","genesisHash":hash(0),"checkpoints":[{"height":0,"hash":hash(0)}],
        "activationHeights":[{"height":0,"upgrade":"Genesis"},{"height":1,"upgrade":"NU6.3"}],
        "subsidy":{"slowStartInterval":0,"slowStartShift":0,"preBlossomHalvingInterval":840000,"postBlossomHalvingInterval":1680000,"fundingStreams":[],"lockboxDisbursements":[{"scriptHash":"12".repeat(20),"amount":0}],"initialNsmValueBalance":null,"allowUnshieldedCoinbaseSpends":false},
        "difficulty":{"targetDifficultyLimitCompact":"1f07ffff","proofOfWork":"disabled","maxBlockTimeStartHeight":653606},"temporaryOrchardDisablingHeight":4048500,"experimental":{"pq":null,"sqisign":null}
    }})
}
pub fn info(height: u32) -> Value {
    let branches = [
        ("Overwinter", "5ba81b19"),
        ("Sapling", "76b809bb"),
        ("Blossom", "2bb40e60"),
        ("Heartwood", "f5b9230b"),
        ("Canopy", "e9ff75a6"),
        ("NU5", "c2d6d0b4"),
        ("NU6", "c8e71055"),
        ("NU6.1", "4dec4df0"),
        ("NU6.2", "5437f330"),
        ("NU6.3", "37a5165b"),
    ];
    let upgrades: serde_json::Map<_, _> = branches
        .iter()
        .map(|(name, branch)| {
            (
                (*branch).into(),
                json!({"name":name,"activationheight":1,"status":"active"}),
            )
        })
        .collect();
    json!({"chain":"test","blocks":height,"bestblockhash":hash(height),"upgrades":upgrades,"consensus":{"chaintip":"37a5165b","nextblock":"37a5165b"}})
}
pub fn node_block(height: u32) -> Value {
    let mut tx = json!({"txid":hash(100+height),"vShieldedSpend":[],"vShieldedOutput":[]});
    if height > 0 {
        tx["ironwood"] = json!({"actions":[{"nullifier":"31".repeat(32),"cmx":"42".repeat(32),"ephemeralKey":"53".repeat(32),"encCiphertext":"64".repeat(580)}]});
    }
    json!({"height":height,"hash":hash(height),"previousblockhash":if height==0 {"00".repeat(32)}else{hash(height-1)},"time":1000+height,
        "trees":{"ironwood":{"size":height}},"tx":[tx]})
}
pub fn compact(height: u32) -> wire::CompactBlock {
    wire::CompactBlock {
        height: height.into(),
        hash: wire_hash(height),
        prev_hash: if height == 0 {
            vec![0; 32]
        } else {
            wire_hash(height - 1)
        },
        time: 1000 + height,
        chain_metadata: Some(wire::ChainMetadata {
            ironwood_commitment_tree_size: height,
            ..Default::default()
        }),
        vtx: if height == 0 {
            vec![]
        } else {
            vec![wire::CompactTx {
                index: 0,
                txid: wire_hash(100 + height),
                ironwood_actions: vec![wire::CompactOrchardAction {
                    nullifier: vec![0x31; 32],
                    cmx: vec![0x42; 32],
                    ephemeral_key: vec![0x53; 32],
                    ciphertext: vec![0x64; 52],
                }],
                ..Default::default()
            }]
        },
        ..Default::default()
    }
}
pub fn tree(height: u32) -> wire::TreeState {
    wire::TreeState {
        network: "test".into(),
        height: height.into(),
        hash: hash(height),
        time: 1000 + height,
        sapling_tree: "000000".into(),
        orchard_tree: "010000".into(),
        ironwood_tree: "020000".into(),
    }
}
pub fn node_tree(height: u32) -> Value {
    json!({"height":height,"hash":hash(height),"time":1000+height,"sapling":{"commitments":{"finalState":"000000"}},"orchard":{"commitments":{"finalState":"010000"}},"ironwood":{"commitments":{"finalState":"020000"}}})
}
pub fn wallet_info() -> wire::LightdInfo {
    wire::LightdInfo {
        version: "v0.5.5".into(),
        chain_name: "test".into(),
        sapling_activation_height: 1,
        consensus_branch_id: "37a5165b".into(),
        block_height: 3,
        lightwallet_protocol_version: "v0.5.0".into(),
        ..Default::default()
    }
}

type Hook = Box<dyn FnMut(&str, &Value, usize) -> Option<Result<Value, RpcError>> + Send>;
pub struct Node {
    pub calls: Mutex<Vec<(String, Value, Duration)>>,
    pub hook: Mutex<Hook>,
}
impl Default for Node {
    fn default() -> Self {
        Self {
            calls: Mutex::default(),
            hook: Mutex::new(Box::new(|_, _, _| None)),
        }
    }
}
impl NodeRpc for Node {
    fn call(&self, method: &str, params: Value, timeout: Duration) -> Result<Value, RpcError> {
        let count = {
            let mut calls = self.calls.lock().unwrap();
            calls.push((method.into(), params.clone(), timeout));
            calls.iter().filter(|c| c.0 == method).count()
        };
        if let Some(value) = (self.hook.lock().unwrap())(method, &params, count) {
            return value;
        }
        Ok(match method {
            "getchainrules" => rules(),
            "getblockchaininfo" => info(3),
            "getbestblockheightandhash" => json!({"height":3,"hash":wire_hash(3)}),
            "getblockhash" => json!(hash(params[0].as_u64().unwrap() as u32)),
            "getblock" => node_block((0..=3).find(|h| params[0] == hash(*h)).unwrap()),
            "z_gettreestate" => node_tree((0..=3).find(|h| params[0] == hash(*h)).unwrap()),
            _ => panic!("unexpected RPC {method}"),
        })
    }
}
#[derive(Default)]
pub struct FakeClock(pub AtomicU64);
impl Clock for FakeClock {
    fn elapsed(&self) -> Duration {
        Duration::from_millis(self.0.load(Ordering::SeqCst))
    }
    fn sleep(&self, d: Duration) {
        self.0.fetch_add(d.as_millis() as u64, Ordering::SeqCst);
    }
}
pub struct Wallet {
    pub info: wire::LightdInfo,
    pub latest: wire::BlockId,
    pub blocks: BTreeMap<u32, wire::CompactBlock>,
    pub tree: wire::TreeState,
    pub error: Mutex<Option<LightwalletError>>,
    pub calls: Mutex<usize>,
}
impl Default for Wallet {
    fn default() -> Self {
        Self {
            info: wallet_info(),
            latest: wire::BlockId {
                height: 3,
                hash: wire_hash(3),
            },
            blocks: (0..=3).map(|h| (h, compact(h))).collect(),
            tree: tree(3),
            error: Mutex::default(),
            calls: Mutex::default(),
        }
    }
}
impl LightwalletRpc for Wallet {
    fn info(&self, _: Duration) -> Result<wire::LightdInfo, LightwalletError> {
        *self.calls.lock().unwrap() += 1;
        if let Some(e) = self.error.lock().unwrap().take() {
            Err(e)
        } else {
            Ok(self.info.clone())
        }
    }
    fn latest_block(&self, _: Duration) -> Result<wire::BlockId, LightwalletError> {
        Ok(self.latest.clone())
    }
    fn block_range(
        &self,
        start: u32,
        end: u32,
        _: Duration,
    ) -> Result<Vec<wire::CompactBlock>, LightwalletError> {
        Ok((start..=end)
            .filter_map(|h| self.blocks.get(&h).cloned())
            .collect())
    }
    fn tree_state(&self, _: u32, _: Duration) -> Result<wire::TreeState, LightwalletError> {
        Ok(self.tree.clone())
    }
}

#[derive(Default)]
pub struct Reply {
    pub messages: Vec<Vec<u8>>,
    pub raw: Option<Vec<u8>>,
    pub status: u16,
    pub delay: Duration,
    pub missing_trailers: bool,
    pub hang: bool,
    pub reset: bool,
}
impl Reply {
    pub fn one(message: &impl Message) -> Self {
        Self {
            messages: vec![message.encode_to_vec()],
            ..Default::default()
        }
    }
}
pub struct GrpcServer {
    pub endpoint: String,
    pub connections: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Drop for GrpcServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let joined = self.thread.take().unwrap().join();
        if !std::thread::panicking() {
            joined.unwrap();
        }
    }
}
pub fn grpc_server(handler: impl Fn(&str, &[u8]) -> Reply + Send + Sync + 'static) -> GrpcServer {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap().to_string();
    listener.set_nonblocking(true).unwrap();
    let connections = Arc::new(AtomicU64::new(0));
    let accepted_connections = connections.clone();
    let stop = Arc::new(AtomicBool::new(false));
    let stopped = stop.clone();
    let handler = Arc::new(handler);
    let thread = std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                while !stopped.load(Ordering::SeqCst) {
                    let Ok(Ok((socket, _))) =
                        tokio::time::timeout(Duration::from_millis(20), listener.accept()).await
                    else {
                        continue;
                    };
                    accepted_connections.fetch_add(1, Ordering::SeqCst);
                    let handler = handler.clone();
                    tokio::spawn(async move {
                        let Ok(mut connection) = h2::server::handshake(socket).await else {
                            return;
                        };
                        while let Some(Ok((request, mut respond))) = connection.accept().await {
                            let handler = handler.clone();
                            tokio::spawn(async move {
                                let path = request.uri().path().to_owned();
                                let mut body = request.into_body();
                                let mut bytes = vec![];
                                while let Some(Ok(data)) = body.data().await {
                                    let size = data.len();
                                    bytes.extend_from_slice(&data);
                                    let _ = body.flow_control().release_capacity(size);
                                }
                                assert!(bytes.len() >= 5);
                                assert_eq!(bytes[0], 0);
                                assert_eq!(
                                    u32::from_be_bytes(bytes[1..5].try_into().unwrap()) as usize,
                                    bytes.len() - 5
                                );
                                let reply = handler(&path, &bytes[5..]);
                                tokio::time::sleep(reply.delay).await;
                                let response = http::Response::builder()
                                    .status(200)
                                    .header("content-type", "application/grpc")
                                    .body(())
                                    .unwrap();
                                let Ok(mut sender) = respond.send_response(response, false) else {
                                    return;
                                };
                                let data = reply.raw.unwrap_or_else(|| {
                                    let mut bytes = Vec::new();
                                    for message in reply.messages {
                                        bytes.push(0);
                                        bytes.extend_from_slice(
                                            &(message.len() as u32).to_be_bytes(),
                                        );
                                        bytes.extend(message);
                                    }
                                    bytes
                                });
                                if !data.is_empty()
                                    && sender
                                        .send_data(bytes::Bytes::from(data), reply.missing_trailers)
                                        .is_err()
                                {
                                    return;
                                }
                                if reply.hang {
                                    tokio::time::sleep(Duration::from_secs(3)).await;
                                    return;
                                }
                                if reply.reset {
                                    sender.send_reset(h2::Reason::INTERNAL_ERROR);
                                    return;
                                }
                                if !reply.missing_trailers {
                                    let mut trailers = http::HeaderMap::new();
                                    trailers.insert(
                                        "grpc-status",
                                        reply.status.to_string().parse().unwrap(),
                                    );
                                    let _ = sender.send_trailers(trailers);
                                }
                            });
                        }
                    });
                }
            });
    });
    GrpcServer {
        endpoint,
        connections,
        stop,
        thread: Some(thread),
    }
}
pub fn good_reply(path: &str, body: &[u8]) -> Reply {
    match path.rsplit('/').next().unwrap() {
        "GetLightdInfo" => Reply::one(&wallet_info()),
        "GetLatestBlock" => Reply::one(&wire::BlockId {
            height: 3,
            hash: wire_hash(3),
        }),
        "GetBlockRange" => {
            let range = wire::BlockRange::decode(body).unwrap();
            assert!(range.pool_types.is_empty());
            let start = range.start.unwrap().height as u32;
            let end = range.end.unwrap().height as u32;
            Reply {
                messages: (start..=end).map(|h| compact(h).encode_to_vec()).collect(),
                ..Default::default()
            }
        }
        "GetTreeState" => {
            let request = wire::BlockId::decode(body).unwrap();
            assert!(request.hash.is_empty());
            Reply::one(&tree(request.height as u32))
        }
        _ => panic!("unexpected gRPC {path}"),
    }
}

pub struct NodeServer {
    pub endpoint: String,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Drop for NodeServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let joined = self.thread.take().unwrap().join();
        if !std::thread::panicking() {
            joined.unwrap();
        }
    }
}
pub fn node_server() -> NodeServer {
    use std::io::{BufRead, BufReader, Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap().to_string();
    listener.set_nonblocking(true).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stopped = stop.clone();
    let thread = std::thread::spawn(move || {
        let node = Node::default();
        while !stopped.load(Ordering::SeqCst) {
            let (mut socket, _) = match listener.accept() {
                Ok(pair) => pair,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(2));
                    continue;
                }
                Err(error) => panic!("{error}"),
            };
            socket.set_nonblocking(false).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut reader = BufReader::new(&mut socket);
            let mut length = 0;
            loop {
                let mut line = String::new();
                assert_ne!(reader.read_line(&mut line).unwrap(), 0);
                if line == "\r\n" {
                    break;
                }
                if line.to_lowercase().starts_with("content-length:") {
                    length = line.split(':').nth(1).unwrap().trim().parse().unwrap();
                }
            }
            let mut bytes = vec![0; length];
            reader.read_exact(&mut bytes).unwrap();
            let request: Value = serde_json::from_slice(&bytes).unwrap();
            let result = node
                .call(
                    request["method"].as_str().unwrap(),
                    request["params"].clone(),
                    Duration::from_secs(1),
                )
                .unwrap();
            let body = json!({"jsonrpc":"2.0","id":request["id"],"result":result}).to_string();
            write!(socket, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",body.len(),body).unwrap();
        }
    });
    NodeServer {
        endpoint,
        stop,
        thread: Some(thread),
    }
}
