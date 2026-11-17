---
title: Storage
description: The key-value storage your app gives the SDK, what the SDK keeps in it, and the rules that keep signing safe across restarts.
---

# Storage

The SDK has no storage of its own. You give it a small key-value store, and it keeps its signing state there: which slots it signed, the constants of each channel, the payment budgets the user approved. That state is what makes deterministic signing safe, so it comes with a few rules.

## The two interfaces

The `storage` option takes either of two shapes. Use the synchronous one when your store is synchronous (an in-memory map in tests, MMKV, `localStorage`), and the async one for everything else (SQLite, IndexedDB, files, AsyncStorage).

```ts
interface ISignerStorage {
    get(key: string): string | null;
    set(key: string, value: string): void;
}

interface IAsyncSignerStorage {
    get(key: string): Promise<string | null>;
    set(key: string, value: string): Promise<void>;
}
```

That is all: `get` returns `null` for a key never written, and `set` overwrites. There is no delete and no listing of keys; the SDK never needs either. Keys and values are strings, the values mostly JSON. See [`ISignerStorage`](/docs/api/interfaces/ISignerStorage) and [`IAsyncSignerStorage`](/docs/api/interfaces/IAsyncSignerStorage).

## A minimal implementation

For tests, a `Map` is enough:

```ts title="memory-storage.ts"
import type { ISignerStorage } from "@peersyst/fiber-lsp-sdk";

// For tests only: it forgets everything when the process ends.
class MemoryStorage implements ISignerStorage {
    private readonly values = new Map<string, string>();

    get(key: string): string | null {
        return this.values.get(key) ?? null;
    }

    set(key: string, value: string): void {
        this.values.set(key, value);
    }
}
```

In an app, wrap your platform's durable store. This adapter also prefixes every key with the tenant id, so several accounts can share one database (see [One storage per master seed](#one-storage-per-master-seed)):

```ts title="signer-storage.ts"
import { FiberLspSdk, deriveTenantId, type IAsyncSignerStorage } from "@peersyst/fiber-lsp-sdk";

// Your platform's durable key-value store (SQLite, MMKV, IndexedDB, a file...).
interface KeyValueStore {
    getItem(key: string): Promise<string | null>;
    setItem(key: string, value: string): Promise<void>;
}

// One storage per master seed: prefix the keys with the tenant id when several accounts share one store.
function signerStorageFor(seed: Uint8Array): IAsyncSignerStorage {
    const prefix = `${deriveTenantId(seed)}/`;
    return {
        get: (key) => kv.getItem(prefix + key),
        // Resolve only once the value is durable: the SDK signs right after this promise settles.
        set: (key, value) => kv.setItem(prefix + key, value),
    };
}

const sdk = new FiberLspSdk(masterSeed, {
    network: "testnet",
    storage: signerStorageFor(masterSeed),
    rpcUrl: "https://lsp.example.com/rpc",
    lspPubkey,
});
```

What the store must guarantee:

- **It survives restarts.** A store that forgets is a store that comes back empty after every launch, which strands every channel (see [Keys and recovery](/docs/concepts/keys-and-recovery#what-a-restore-does-not-bring-back)).
- **A write is durable when `set` returns** (or its promise resolves). The SDK writes a slot's claim and then signs. A claim that was only buffered and lost in a crash would leave the slot looking free.
- **`get` returns what was last `set`**, as a string, byte for byte.

React Native specifics (which stores work, and how) are in the [React Native guide](/docs/guides/react-native).

## What is stored

Every key the SDK writes starts with `fiber-lsp-sdk:`, so the SDK can share a store with your own keys without colliding.

| Key | What it holds |
| --- | --- |
| `fiber-lsp-sdk:channel:<index>` | One record per channel: the sign-once registry, the last commitments signed, the values pinned at the opening, the revocation evidence, the watchtower's spends |
| `fiber-lsp-sdk:alias:<channelId>` | Which channel index a channel id points to (Fiber renames a channel once during its opening) |
| `fiber-lsp-sdk:intent:<hash>` | The budget the user approved for a payment sent |
| `fiber-lsp-sdk:invoice:<hash>` | A hold invoice the device created, with the index its preimage derives from |
| `fiber-lsp-sdk:allocator:<kind>` | The last channel or invoice index handed out |
| `fiber-lsp-sdk:activity` | The channels, invoices and payments the poller still follows |
| `fiber-lsp-sdk:opening` | The channel opening in progress, so a retry resumes it |
| `fiber-lsp-sdk:device-channels` | The channels this device opened, kept while the watchtower may still ask about them |

**No secret is ever stored.** Keys and preimages are derived from the master seed when needed. A leaked copy of the storage tells an attacker about the user's channels and payments, but cannot sign anything.

A value the SDK cannot read is never treated as missing: a corrupt record throws, and signing on that channel stops until it is fixed. Treating it as empty would reopen slots that were already signed.

## One storage per master seed

A storage (or one key prefix of a shared store) belongs to exactly one master seed. Some records, such as the opening in progress and the activity list, are single keys a second seed would overwrite or read as its own. If your wallet has several accounts, give each its own store, or prefix the keys with [`deriveTenantId(masterSeed)`](/docs/api/functions/deriveTenantId) as the adapter above does.

And give a storage to **one SDK instance at a time**. The SDK serializes its own operations on each key, so you never need locks for a single instance, but two instances over the same storage (a second tab, a second process, a second `new FiberLspSdk` in a hot reload) can overwrite each other's claims. `ISignerStorage` has no compare-and-swap that the SDK could protect itself with.

## Never older than it was

This is the rule that matters most. The storage may come back **empty**: the SDK then knows no channel and refuses everything, which is safe. It must never come back **older** than it was.

An older copy still has the channels and their aliases, but not the slots signed since. The SDK would read those slots as free, and the node could have them signed again under the same deterministic nonces. A few signatures under one nonce are enough to compute the channel's funding key, and with it, the funds. [No blind signing](/docs/concepts/no-blind-signing#sign-once) explains why.

:::danger[Keep the SDK's storage out of backups]
An OS or cloud backup that restores app data (iCloud, Android Auto Backup, a copied browser profile, a file restored from a snapshot) is exactly an older state. Exclude the SDK's store from them, and never restore one over a live device. The mnemonic is the backup: it brings back every key.
:::

What a restore from the mnemonic does and does not recover is in [Keys and recovery](/docs/concepts/keys-and-recovery#what-a-restore-does-not-bring-back).

## Concurrency

Inside one instance the SDK runs the operations on each key one at a time, in call order, and different keys never wait on each other. Your async store may therefore see concurrent `get` and `set` calls on *different* keys, never two overlapping operations it has to order on the same key. Signing decisions additionally run one at a time across all channels, because the payment budgets they check are shared.

## What grows

Nothing is ever deleted, on purpose: closure is something the node reports, and deleting on the node's word would let it clear the records that refuse it. In practice:

- **A channel's record** grows by roughly 85 bytes per slot signed and 170 bytes per update, and is rewritten on every signature. A channel a thousand updates deep is a record of about 300 KB.
- **Each payment and invoice** leaves a record of about 200 bytes: ten thousand of them are about 2 MB.
- **Channel ids** cost under 200 bytes per channel, forever.
- The activity list, the opening and the list of channels stay small: they drop what is finished.

Pick a store where rewriting a few hundred KB per signature is cheap. A store that serializes everything into one blob on each write will slow down as channels age.

## Learn more

- [Keys and recovery](/docs/concepts/keys-and-recovery): what comes back from the mnemonic.
- [Security](/docs/resources/security): the threat model.
- Every record and its fields: [`docs/persistence.md`](https://github.com/Peersyst/fiber-lsp-sdk/blob/main/docs/persistence.md).
