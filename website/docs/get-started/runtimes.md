---
title: Runtimes
description: Run the Fiber LSP SDK unmodified in Node, browsers and React Native, and what to choose differently in each.
---

# Runtimes

The same package runs unmodified in Node, in browsers and in React Native on Hermes. The SDK code is identical everywhere; what changes from one runtime to another is the storage you give it and, on React Native, the `fetch`.

## What is the same everywhere

The SDK makes no platform call of its own. It needs only what all three runtimes have: a global `fetch`, `setTimeout` and `clearTimeout`, `Date.now` and `TextEncoder`. It draws no randomness. The storage is the one effect with no shared default, because no key-value store exists in all three runtimes.

Whatever the runtime, two rules hold for the storage:

- **It must never go back to an older state.** Restoring it from a backup can make the device sign twice under the same nonce, which reveals the channel's funding key. Coming back empty is safe; coming back older is not.
- **One SDK instance per storage.** Two instances over the same store (two tabs, two processes) can overwrite each other's records, because the storage has no compare-and-swap.

[Storage](/docs/concepts/storage) explains both.

## Node

Node 20.19 or later, with ESM or CommonJS. Back the storage with a database or a file that you write durably, and keep it out of any restore-from-backup process. A synchronous `ISignerStorage` or an asynchronous `IAsyncSignerStorage` both work:

```ts title="storage.ts"
import type { IAsyncSignerStorage } from "@peersyst/fiber-lsp-sdk";

// An async store over your database: the SDK awaits every read and write.
const storage: IAsyncSignerStorage = {
    get: async (key) => (await db.getValue(key)) ?? null,
    set: (key, value) => db.putValue(key, value),
};
```

Node is also where the LSP operator's backend runs `LspOperatorClient`. It needs no storage.

## Browsers

The build targets ES2022 and uses no browser-specific API, so a browser with ES2022 support runs it. For the storage, IndexedDB behind an `IAsyncSignerStorage` is the usual choice.

Two browser-specific cautions:

- **Tabs.** A second tab that builds its own `FiberLspSdk` over the same IndexedDB database breaks the one-instance rule. Make sure only one tab runs the SDK at a time.
- **Cleared site data.** A user who clears site data empties the storage. That is the safe direction (the device then refuses to sign for channels it no longer knows), but the device loses its channel records. See what a wipe costs in [Status and known limitations](/docs/resources/status).

## React Native (Hermes)

The package runs on Hermes with the new architecture, bundled by Metro with no extra configuration and no polyfill. Two things are different:

- **Storage.** A synchronous `ISignerStorage` over MMKV works. MMKV survives the app being killed but not a power loss, after which it may reload an earlier state. A store that syncs before it returns, such as SQLite with `synchronous=FULL` behind an `IAsyncSignerStorage`, closes that gap. Either way, exclude it from Android's Auto Backup.
- **Fetch timeout.** React Native's global `fetch` has no timeout on Android, so a half-open connection can hang every later request. Pass your own `fetch` with a deadline, long enough for a channel opening, which blocks until the funding transaction is built:

```ts title="fetch.ts"
import type { IFetchLike } from "@peersyst/fiber-lsp-sdk";

// React Native's fetch has no timeout on Android: give every call a deadline.
const fetchWithTimeout: IFetchLike = async (url, init) => {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 120_000);
    try {
        return await fetch(url, { ...init, signal: controller.signal });
    } finally {
        clearTimeout(timeout);
    }
};
```

Then pass it as the `fetch` option. Your app also needs a secure random source for the tenant registration's request id, which Hermes does not provide on its own.

:::info
Backgrounding matters most on mobile: a device in the background answers no signing request, and Fiber force-closes a channel left waiting mid-round for about 30 seconds. Read [React Native](/docs/guides/react-native) and [Backgrounding](/docs/guides/backgrounding) before you ship.
:::

## Next steps

- [React Native](/docs/guides/react-native): the full mobile setup.
- [Compatibility](/docs/resources/compatibility): the tested versions of each runtime.
