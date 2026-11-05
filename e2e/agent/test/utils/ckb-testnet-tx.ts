import type { CkbTxJson } from "../../src/ckb-tx";

// A public channel's funding tx committed on CKB testnet, as `get_transaction` returns it less its `hash`: two inputs under two
// default locks, each signed by its fnn's own wallet, so the hash and both witnesses are CKB's word, not this package's.
export const TESTNET_TX_HASH = "0xed2ef08ead105e404adca9b0d921773cb642dcedf8012d106722ba86a6946589";

export const TESTNET_TX: CkbTxJson = {
    version: "0x0",
    cell_deps: [
        {
            out_point: { tx_hash: "0xf8de3bb47d055cdf460d93a2a6e1b05f7432f9777c8c474abf4eec1d4aee5d37", index: "0x0" },
            dep_type: "dep_group",
        },
    ],
    header_deps: [],
    inputs: [
        {
            previous_output: { tx_hash: "0xa87cffdc2ebdb9bfe82b0ae1ecc51f47ace9bf5ef0ee90668cdb261f580dd61f", index: "0x0" },
            since: "0x0",
        },
        {
            previous_output: { tx_hash: "0xe3d987c0842e322db7d19b2266433af2b87aac92d49ea56f44324d7d127c83fc", index: "0x0" },
            since: "0x0",
        },
    ],
    outputs: [
        {
            capacity: "0x174876e800",
            lock: {
                code_hash: "0x6c67887fe201ee0c7853f1682c0b77c0e6214044c156c7558269390a8afa6d7c",
                hash_type: "type",
                args: "0x78f21e275bbd2f597be0c7775b4d82352609ad2f",
            },
            type: null,
        },
        {
            capacity: "0x68c6171230",
            lock: {
                code_hash: "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
                hash_type: "type",
                args: "0x9d937955050c4fb22408d338f096a6530ddd1de1",
            },
            type: null,
        },
        {
            capacity: "0xae9f7bcb0a",
            lock: {
                code_hash: "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
                hash_type: "type",
                args: "0x8e0e0590f4a1b5d38e19f9bd58e9e3d0ae6ad9c6",
            },
            type: null,
        },
    ],
    outputs_data: ["0x", "0x", "0x"],
    witnesses: [
        "0x5500000010000000550000005500000041000000a9236751878f5d222414a855601464bfd2c5c5cae11319102daab905faf9b86c22d2a2f53d73ff71c01259b9846f4a3905a44d2cbabe10e1b4c3dd86c2e283c200",
        "0x55000000100000005500000055000000410000008eaec2d27b01acddeb31614004d190d5d724759d6240aa785628b75dac54bbb61ee7328336a50394b2090fcb171a86ee28ad5848d878ba9dd88275267f904a2400",
    ],
};

// The locks of the cells the two inputs spend, read from their txs on testnet.
export const TESTNET_INPUT_LOCK_ARGS = [
    "0x9d937955050c4fb22408d338f096a6530ddd1de1",
    "0x8e0e0590f4a1b5d38e19f9bd58e9e3d0ae6ad9c6",
] as const;

// A balance split into cells of 270 CKB, signed by this package and committed on testnet: its two inputs are one group under one
// default lock, so CKB took the one signature over a message that covers the second input's empty witness.
export const TESTNET_GROUP_TX_HASH = "0x6fa2dd1248e03f46d79e2ea975d1d94ad165f0a8df9123c7cfcb2108fa77eee2";

export const TESTNET_GROUP_TX: CkbTxJson = {
    version: "0x0",
    cell_deps: [
        {
            out_point: {
                tx_hash: "0xf8de3bb47d055cdf460d93a2a6e1b05f7432f9777c8c474abf4eec1d4aee5d37",
                index: "0x0",
            },
            dep_type: "dep_group",
        },
    ],
    header_deps: [],
    inputs: [
        {
            previous_output: {
                tx_hash: "0x0f495271585f1539e400d332810395ef9f5dc0612826f37597d28841878e6f71",
                index: "0x2",
            },
            since: "0x0",
        },
        {
            previous_output: {
                tx_hash: "0xbfd9b7e6ab2447281af04d1ebfaca2eaa25740a3f51224ba9b1b09ddcb789ff5",
                index: "0x0",
            },
            since: "0x0",
        },
    ],
    outputs: [
        {
            capacity: "0x649534e00",
            lock: {
                code_hash: "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
                hash_type: "type",
                args: "0x9d937955050c4fb22408d338f096a6530ddd1de1",
            },
            type: null,
        },
        {
            capacity: "0x649534e00",
            lock: {
                code_hash: "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
                hash_type: "type",
                args: "0x9d937955050c4fb22408d338f096a6530ddd1de1",
            },
            type: null,
        },
        {
            capacity: "0x649534e00",
            lock: {
                code_hash: "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
                hash_type: "type",
                args: "0x9d937955050c4fb22408d338f096a6530ddd1de1",
            },
            type: null,
        },
        {
            capacity: "0x649534e00",
            lock: {
                code_hash: "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
                hash_type: "type",
                args: "0x9d937955050c4fb22408d338f096a6530ddd1de1",
            },
            type: null,
        },
        {
            capacity: "0x649534e00",
            lock: {
                code_hash: "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
                hash_type: "type",
                args: "0x9d937955050c4fb22408d338f096a6530ddd1de1",
            },
            type: null,
        },
        {
            capacity: "0x649534e00",
            lock: {
                code_hash: "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
                hash_type: "type",
                args: "0x9d937955050c4fb22408d338f096a6530ddd1de1",
            },
            type: null,
        },
        {
            capacity: "0x649534e00",
            lock: {
                code_hash: "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
                hash_type: "type",
                args: "0x9d937955050c4fb22408d338f096a6530ddd1de1",
            },
            type: null,
        },
        {
            capacity: "0x649534e00",
            lock: {
                code_hash: "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
                hash_type: "type",
                args: "0x9d937955050c4fb22408d338f096a6530ddd1de1",
            },
            type: null,
        },
        {
            capacity: "0x649534e00",
            lock: {
                code_hash: "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
                hash_type: "type",
                args: "0x9d937955050c4fb22408d338f096a6530ddd1de1",
            },
            type: null,
        },
        {
            capacity: "0x649534e00",
            lock: {
                code_hash: "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
                hash_type: "type",
                args: "0x9d937955050c4fb22408d338f096a6530ddd1de1",
            },
            type: null,
        },
        {
            capacity: "0x649534e00",
            lock: {
                code_hash: "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
                hash_type: "type",
                args: "0x9d937955050c4fb22408d338f096a6530ddd1de1",
            },
            type: null,
        },
        {
            capacity: "0x649534e00",
            lock: {
                code_hash: "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
                hash_type: "type",
                args: "0x9d937955050c4fb22408d338f096a6530ddd1de1",
            },
            type: null,
        },
        {
            capacity: "0x649534e00",
            lock: {
                code_hash: "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
                hash_type: "type",
                args: "0x9d937955050c4fb22408d338f096a6530ddd1de1",
            },
            type: null,
        },
        {
            capacity: "0x649534e00",
            lock: {
                code_hash: "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
                hash_type: "type",
                args: "0x9d937955050c4fb22408d338f096a6530ddd1de1",
            },
            type: null,
        },
        {
            capacity: "0x649534e00",
            lock: {
                code_hash: "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
                hash_type: "type",
                args: "0x9d937955050c4fb22408d338f096a6530ddd1de1",
            },
            type: null,
        },
        {
            capacity: "0x649534e00",
            lock: {
                code_hash: "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
                hash_type: "type",
                args: "0x9d937955050c4fb22408d338f096a6530ddd1de1",
            },
            type: null,
        },
        {
            capacity: "0x649534e00",
            lock: {
                code_hash: "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
                hash_type: "type",
                args: "0x9d937955050c4fb22408d338f096a6530ddd1de1",
            },
            type: null,
        },
        {
            capacity: "0x649534e00",
            lock: {
                code_hash: "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
                hash_type: "type",
                args: "0x9d937955050c4fb22408d338f096a6530ddd1de1",
            },
            type: null,
        },
        {
            capacity: "0x649534e00",
            lock: {
                code_hash: "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
                hash_type: "type",
                args: "0x9d937955050c4fb22408d338f096a6530ddd1de1",
            },
            type: null,
        },
        {
            capacity: "0x649534e00",
            lock: {
                code_hash: "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
                hash_type: "type",
                args: "0x9d937955050c4fb22408d338f096a6530ddd1de1",
            },
            type: null,
        },
        {
            capacity: "0x649534e00",
            lock: {
                code_hash: "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
                hash_type: "type",
                args: "0x9d937955050c4fb22408d338f096a6530ddd1de1",
            },
            type: null,
        },
        {
            capacity: "0x649534e00",
            lock: {
                code_hash: "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
                hash_type: "type",
                args: "0x9d937955050c4fb22408d338f096a6530ddd1de1",
            },
            type: null,
        },
        {
            capacity: "0x649534e00",
            lock: {
                code_hash: "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
                hash_type: "type",
                args: "0x9d937955050c4fb22408d338f096a6530ddd1de1",
            },
            type: null,
        },
        {
            capacity: "0x649534e00",
            lock: {
                code_hash: "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
                hash_type: "type",
                args: "0x9d937955050c4fb22408d338f096a6530ddd1de1",
            },
            type: null,
        },
        {
            capacity: "0x9c7639a9a",
            lock: {
                code_hash: "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
                hash_type: "type",
                args: "0x9d937955050c4fb22408d338f096a6530ddd1de1",
            },
            type: null,
        },
    ],
    outputs_data: [
        "0x",
        "0x",
        "0x",
        "0x",
        "0x",
        "0x",
        "0x",
        "0x",
        "0x",
        "0x",
        "0x",
        "0x",
        "0x",
        "0x",
        "0x",
        "0x",
        "0x",
        "0x",
        "0x",
        "0x",
        "0x",
        "0x",
        "0x",
        "0x",
        "0x",
    ],
    witnesses: [
        "0x5500000010000000550000005500000041000000dfc1074d4ba04f909773831ac2b5cc84506ba778cc43171977c1d11bc2cb963f6b643ead299db5a6f9b99be50038877f1443bef0ad0417ef91ef7c2b9d8adbfa00",
        "0x",
    ],
};

// Two txs made for these vectors and committed on testnet, both signed by this package for one key. The first has a since,
// an output with a type (a type id) and outputs under the default lock's code by data hash, run as data, data1 and data2; the
// second spends those four outputs, one group each, with a since again and the code and its data as `code` deps.
export const TESTNET_TYPED_TX_HASH = "0x6861de3b71514664b32aae1bb7ef6dbf52e1b249c2974423994a244127c5e620";

export const TESTNET_TYPED_TX: CkbTxJson = {
    version: "0x0",
    cell_deps: [
        {
            out_point: {
                tx_hash: "0xf8de3bb47d055cdf460d93a2a6e1b05f7432f9777c8c474abf4eec1d4aee5d37",
                index: "0x0",
            },
            dep_type: "dep_group",
        },
    ],
    header_deps: [],
    inputs: [
        {
            previous_output: {
                index: "0x18",
                tx_hash: "0x6fa2dd1248e03f46d79e2ea975d1d94ad165f0a8df9123c7cfcb2108fa77eee2",
            },
            since: "0x1",
        },
        {
            previous_output: {
                index: "0x1",
                tx_hash: "0x719096db17a1cc6fb84ab775b3dca03d7e1f1ca71d6937c59559f69d45125ea9",
            },
            since: "0x0",
        },
    ],
    outputs: [
        {
            capacity: "0x306dc4200",
            lock: {
                code_hash: "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
                hash_type: "type",
                args: "0x9d937955050c4fb22408d338f096a6530ddd1de1",
            },
            type: {
                code_hash: "0x00000000000000000000000000000000000000000000000000545950455f4944",
                hash_type: "type",
                args: "0x6676a2a33a1d809b5b6efc958c20c097aa888daab54feb37318f3b2e3af7edde",
            },
        },
        {
            capacity: "0x1a13b8600",
            lock: {
                code_hash: "0x709f3fda12f561cfacf92273c57a98fede188a3f1a59b1f888d113f9cce08649",
                hash_type: "data",
                args: "0x9d937955050c4fb22408d338f096a6530ddd1de1",
            },
            type: null,
        },
        {
            capacity: "0x1a13b8600",
            lock: {
                code_hash: "0x709f3fda12f561cfacf92273c57a98fede188a3f1a59b1f888d113f9cce08649",
                hash_type: "data1",
                args: "0x9d937955050c4fb22408d338f096a6530ddd1de1",
            },
            type: null,
        },
        {
            capacity: "0x1a13b8600",
            lock: {
                code_hash: "0x709f3fda12f561cfacf92273c57a98fede188a3f1a59b1f888d113f9cce08649",
                hash_type: "data2",
                args: "0x9d937955050c4fb22408d338f096a6530ddd1de1",
            },
            type: null,
        },
        {
            capacity: "0x37e0ec42a",
            lock: {
                code_hash: "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
                hash_type: "type",
                args: "0x9d937955050c4fb22408d338f096a6530ddd1de1",
            },
            type: null,
        },
    ],
    outputs_data: ["0x", "0x", "0x", "0x", "0x"],
    witnesses: [
        "0x55000000100000005500000055000000410000000c0302307ef7196af6c9d36fca135463b61def1b9d6d8d280a51879a6ce0269f2923bd3c597f80022ae650a760e58067eed1df4c2e0a516b6da92e9e0402337401",
        "0x",
    ],
};

export const TESTNET_CODE_DEPS_TX_HASH = "0x6bf657cbc50d6d23ada47a5c20f79d7752adacd14491f3c57eeb55c4f88474bf";

export const TESTNET_CODE_DEPS_TX: CkbTxJson = {
    version: "0x0",
    cell_deps: [
        {
            out_point: {
                tx_hash: "0x8f8c79eb6671709633fe6a46de93c0fedc9c1b8a6527a18d3983879542635c9f",
                index: "0x1",
            },
            dep_type: "code",
        },
        {
            out_point: {
                tx_hash: "0x8f8c79eb6671709633fe6a46de93c0fedc9c1b8a6527a18d3983879542635c9f",
                index: "0x3",
            },
            dep_type: "code",
        },
    ],
    header_deps: [],
    inputs: [
        {
            previous_output: {
                tx_hash: "0x6861de3b71514664b32aae1bb7ef6dbf52e1b249c2974423994a244127c5e620",
                index: "0x0",
            },
            since: "0x0",
        },
        {
            previous_output: {
                tx_hash: "0x6861de3b71514664b32aae1bb7ef6dbf52e1b249c2974423994a244127c5e620",
                index: "0x1",
            },
            since: "0x2",
        },
        {
            previous_output: {
                tx_hash: "0x6861de3b71514664b32aae1bb7ef6dbf52e1b249c2974423994a244127c5e620",
                index: "0x2",
            },
            since: "0x0",
        },
        {
            previous_output: {
                tx_hash: "0x6861de3b71514664b32aae1bb7ef6dbf52e1b249c2974423994a244127c5e620",
                index: "0x3",
            },
            since: "0x0",
        },
    ],
    outputs: [
        {
            capacity: "0x7ea8d4d60",
            lock: {
                code_hash: "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
                hash_type: "type",
                args: "0x9d937955050c4fb22408d338f096a6530ddd1de1",
            },
            type: null,
        },
    ],
    outputs_data: ["0x"],
    witnesses: [
        "0x5500000010000000550000005500000041000000755b21b8af4d3ec61cf4118a4efe8ef299667079a4c4017ceda42484c0e92dee638c5c6be8609185c401b603703e7d711ec3b2498f3fcc6a61027b17cb47ad4501",
        "0x5500000010000000550000005500000041000000755b21b8af4d3ec61cf4118a4efe8ef299667079a4c4017ceda42484c0e92dee638c5c6be8609185c401b603703e7d711ec3b2498f3fcc6a61027b17cb47ad4501",
        "0x5500000010000000550000005500000041000000755b21b8af4d3ec61cf4118a4efe8ef299667079a4c4017ceda42484c0e92dee638c5c6be8609185c401b603703e7d711ec3b2498f3fcc6a61027b17cb47ad4501",
        "0x5500000010000000550000005500000041000000755b21b8af4d3ec61cf4118a4efe8ef299667079a4c4017ceda42484c0e92dee638c5c6be8609185c401b603703e7d711ec3b2498f3fcc6a61027b17cb47ad4501",
    ],
};
