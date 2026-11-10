# React Native

What running the SDK in a React Native app takes beyond what any host provides
([sdk.md](./sdk.md), "The effects it is given"). This page covers Android; iOS has its own background rules, not described
here.

## What the package needs

The published package runs as it is in an app on Expo 55, React Native 0.83, Hermes and the new architecture, bundled by
Metro with no configuration. An app already on `@noble/*` or `@scure/*` v1 installs the SDK's v2 beside them, each resolved
by its importer.

It needs no polyfill: the only web API it uses that a runtime may lack is `TextEncoder`, which Hermes provides, and it draws
no randomness.

## What the app provides

- **The storage.** A synchronous `ISignerStorage` over MMKV serves it, values stored as the strings the SDK writes, one per
  master seed ([persistence.md](./persistence.md), "Keyspace"). It must never come back older than it was
  ([persistence.md](./persistence.md), "Recovery"), so the app keeps it out of the OS's backups: Android's Auto Backup through
  `dataExtractionRules` or `fullBackupContent`. MMKV writes through a memory map it does not sync, so it survives the app's
  process being killed but not a power loss or an OS crash, after which its recovery may reload an earlier state. A store that
  syncs before it returns, such as an `IAsyncSignerStorage` over SQLite with `synchronous=FULL`, closes that gap.
- **The fetch.** React Native's global `fetch` has no timeout on Android: its OkHttp client connects, reads and writes with
  none. A half-open connection hangs a request for good, and since OkHttp runs at most 5 calls per host, hung requests end up
  holding back every later one. The app passes its own `fetch` with an `AbortController` deadline, long enough for an opening's
  prepare ([rpc.md](./rpc.md), "Time out").

## In the background

A backgrounded app is a device absent from the round, and so is a killed one until its relaunch rebuilds the facade on its
storage. Both are held to the budget of a round ([sdk.md](./sdk.md), "`connect()` and `disconnect()`").

A facade left connected stops polling: React Native pauses its timers on Android, so the poller's next tick waits for the
return, within one interval of it. Recent Android also freezes cached apps, so no response reaches the JavaScript and nothing
is read or signed. Without that freezer, a step in flight may complete, and sign, in the background.

A step in flight settles on the return. If the app was away past the step's thirty seconds, its deadline may fire first and
report it once as a `poll_failed` ("the step did not settle"), or the step completes. Either way the next tick reads afresh
([sdk.md](./sdk.md), "What is watched, and the poller"). A host that calls `disconnect()` on the way out abandons that step
instead and hears nothing of it.
