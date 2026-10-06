# Invoices

Fiber's invoice string, read and written by the device itself. The device needs it twice: to know which payment hash it is
authorizing when the user pays an invoice, since the hash the node reports is the node's word and not the string's, and to
check that the string the node returns for an invoice the device asked for carries the hash, amount and expiry it asked for.
Both need a reader that sees what fiber's decoder sees, so the `invoice` module is a port, pinned against fiber's own encoder
and decoder by vectors of its own.

Every claim about fiber refers to `nervosnetwork/fiber` @ `b71a61c3`, `crates/fiber-types/src/invoice.rs` unless another file
is named.

## The string

`bech32m(hrp, [flag] ++ groups(compressed) ++ groups(signature))`, with no length cap:

| Part                | What it is                                                                                                         |
| ------------------- | ------------------------------------------------------------------------------------------------------------------ |
| Human-readable part | `fibb`, `fibt` or `fibd` (mainnet, testnet, any other chain), then the amount in shannons in plain decimal, if any |
| Flag                | One five-bit group: `1` signed, `0` not                                                                            |
| Compressed data     | The molecule `RawInvoiceData` compressed by the arithmetic coder, regrouped into five-bit groups and zero padded   |
| Signature           | `r ‖ s ‖ recovery id`, 65 bytes, as exactly 104 groups; never compressed                                           |

The amount has no multiplier, so `fibt250000000` is 2.5 CKB. Currency and amount live only in the human-readable part, and
everything else in `RawInvoiceData`: a table of the timestamp (`u128`, milliseconds), the payment hash and a vector of
attributes, each a union item:

| Id  | Attribute                     | SDK type                      | Value                                                  |
| --- | ----------------------------- | ----------------------------- | ------------------------------------------------------ |
| 0   | `ExpiryTime`                  | `expiryTime`                  | `u64` seconds                                          |
| 1   | `Description`                 | `description`                 | UTF-8                                                  |
| 2   | `FinalHtlcTimeout`            | `finalHtlcTimeout`            | `u64` milliseconds; deprecated, still read and written |
| 3   | `FinalHtlcMinimumExpiryDelta` | `finalHtlcMinimumExpiryDelta` | `u64` milliseconds                                     |
| 4   | `FallbackAddr`                | `fallbackAddr`                | UTF-8                                                  |
| 5   | `Feature`                     | `feature`                     | Fiber's feature bit vector, kept as the bytes it is    |
| 6   | `UdtScript`                   | `udtScript`                   | A CKB `Script`                                         |
| 7   | `PayeePublicKey`              | `payeePublicKey`              | A compressed secp256k1 key                             |
| 8   | `HashAlgorithm`               | `hashAlgorithm`               | One byte: `0` ckb-hash, `1` sha256                     |
| 9   | `PaymentSecret`               | `paymentSecret`               | 32 bytes                                               |

The attributes keep their order: it is part of the bytes the signature covers. The payee signs
`sha256(hrp ‖ compressed ‖ one zero byte when the compressed length is not a multiple of five)`, the bytes fiber's five-bit
padding of the stream comes to (`construct_invoice_preimage`). `computeInvoiceDigest` computes it.

## The arithmetic coder

The data is compressed by the `arcode` 0.2.4 crate as fiber configures it (`ar_encompress`, `ar_decompress_with_limit`): 48
bits of precision, an adaptive model over the 256 byte values and an end marker, every count starting at one and the count
of a byte raised after it is coded. `arithmetic-coder.ts` is a port of it, small once three things are known:

- **The range arithmetic is floating point.** The crate computes `low + (width as f64 * probability) as u64`, the probability
  itself a division. The port does the same in `Number` (`low + Math.floor(width * (cumulative / total))`), which is exact
  here because every value stays below 2^49. Integer division rounds differently and diverges within a few symbols.
- **The decoder pads a short input with zero bits**, as many as its precision, and fails on the next one. So a stream cut
  short can still decode, sometimes to other data.
- **The decoder stops at the end marker**, so what follows the marker in the stream, and the low bits of the last byte, are
  never read.

A payload past 16384 bytes is refused while decompressing, as fiber does, which bounds what a short string can expand to.

## One invoice, one string

Fiber's decoder accepts strings its encoder would never write: an uppercase string, an amount with leading zeros, a stream
with bytes after its end marker or different low bits, an uncompressed payee key, an unknown hash algorithm byte. It accepts
them because it checks the signature over its own re-encoding of what it read, not over the bytes it received. So several
strings are one invoice with one valid signature.

The SDK reads exactly one string per invoice, the one fiber's encoder writes, and refuses the rest naming the layer:

| Layer        | What is refused                                                                                                                                                                                                        |
| ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `invoice`    | Any uppercase character, no separator, a character outside the charset, a plain bech32 or broken checksum                                                                                                              |
| `currency`   | A prefix other than `fibb`, `fibt`, `fibd`                                                                                                                                                                             |
| `amount`     | Anything but canonical decimal within `u128`: a leading zero, a sign, a multiplier                                                                                                                                     |
| `flag`       | Anything but the signed flag                                                                                                                                                                                           |
| `compressed` | Padding that is not zero or is a whole group, a stream that runs out, data past 16384 bytes, and any stream other than the one the coder writes for its data                                                           |
| `data…`      | Whatever molecule's strict reader refuses, invalid UTF-8, a payee key that is not a 33-byte compressed point, a hash algorithm byte other than 0 or 1, a script hash type CKB does not define, an attribute type twice |
| `signature`  | `r` or `s` out of range, a recovery id past 3, a high-S signature, one that recovers no key, and one not by the payee key the invoice carries                                                                          |

The stream check is a re-encoding: the data is compressed again and must give the very bytes received. The other layers are
canonical by construction: strict padding leaves one group count per byte length, and molecule's strict layout leaves one
serialization per value. `encodeInvoice` refuses, for its part, whatever `decodeInvoice` would refuse except the signature,
which it writes as given, as fiber's `Display` does.

What fiber's decoder accepts and writes back unchanged is accepted too, though only fiber's invoice builder would refuse it: a
zero amount, a multi-path feature without a payment secret, a description longer than the builder's 639 bytes, the
deprecated `FinalHtlcTimeout`. Those are rules about creating invoices, not about the format.

## Where the SDK parts from fiber

The rule above removes the strings fiber rewrites. Five more differences are deliberate, each pinned by a variant of the
vectors:

| Fiber                                                                                     | The SDK                                        | Why                                                                                                                   |
| ----------------------------------------------------------------------------------------- | ---------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| Reads unsigned invoices (`from_str_allowing_unsigned`)                                    | Signed only                                    | `send_payment` reads with the signed-only reader, and every unsigned path of fiber's decoder is where its defects are |
| Reads an attribute type twice, its getters returning the first                            | Refuses it                                     | Fiber's builder never writes one, and a second reader would have to agree on "the first"                              |
| Verifies the signature against the payee key and never compares the recovered key with it | Requires the recovered key to be the payee key | Otherwise a flipped recovery id is a second string for one invoice                                                    |
| Reads any `hash_type` byte of a UDT script                                                | Refuses one CKB does not define                | The SDK's `Script` cannot carry it                                                                                    |
| Panics on a string of exactly 104 data groups with the signed flag                        | Refuses it                                     | A crash on untrusted input                                                                                            |

An invoice without a payee key is read as fiber reads it: whatever key the signature recovers to is its payee, so a flipped
recovery id or a signature over other bytes gives another, valid-looking invoice. Fiber cannot pay one from its string alone
(`send_payment` takes the target from the attribute), and what a caller does with one is the caller's decision, not the
reader's.

## Where it lives

| File                                  | Contents                                                                                                      |
| ------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| `src/invoice/invoice.ts`              | `decodeInvoice`, `encodeInvoice`, `computeInvoiceDigest`: the human-readable part and the signature           |
| `src/invoice/invoice-data.ts`         | `RawInvoiceData` and its ten attributes, written and read strictly                                            |
| `src/invoice/arithmetic-coder.ts`     | The port of `arcode`                                                                                          |
| `src/invoice/bech32m.ts`              | The checksum, the charset and the strict five-to-eight regrouping                                             |
| `src/invoice/utils/molecule.utils.ts` | Molecule's strict readers: table, dynvec, `Bytes`, fixed values, union, `Script`                              |
| `src/invoice/utils/utf8.utils.ts`     | UTF-8 both ways, as Rust's `String::from_utf8` reads it; the platform's `TextDecoder` is not in every runtime |
| `src/invoice/invoice.error.ts`        | `InvoiceError`: the path refused and what it had to be, never the value                                       |
| `src/common/utils/molecule.utils.ts`  | The molecule writers `invoice` shares with `digest`                                                           |

The barrel lists its exports one by one, as the other ports' do: the three functions, the types, the error and the constants.

## What the vectors guarantee

`interop/vectors/invoice.json` is written by the harness from fiber's own types (see [interop/README.md](../interop/README.md)):

- **Invoices fiber wrote**: each attribute alone and all together, the three currencies, no amount and `u128::MAX`, signed and
  unsigned, the hold invoice and the multi-path invoice as `new_invoice` shapes them, and data of exactly 16384 bytes. Each
  carries its molecule, its compressed stream, its digest and its signature besides the string, so a divergence names its layer,
  and the harness checks its own encoding of each against fiber's `Display`.
- **The coder past what an invoice reaches**: streams for every byte value, a long run, pseudo-random data of up to 16384
  bytes; and streams the decoder reads past what the coder wrote or refuses: bytes after the marker, every bit of the last byte
  flipped, one to seven bytes cut.
- **UTF-8 as Rust reads it**: every boundary of every width, overlong forms, surrogates, past U+10FFFF, cut sequences.
- **Variants of one invoice with fiber's verdict**: 67 strings, each marked accepted, rewritten, refused or panicked by fiber's
  signed-only decoder. The SDK accepts a variant exactly when fiber accepts it and writes it back unchanged, save four
  variants of the table's differences whose strings fiber accepts as they are, each with the refusal it must end in; the panic is refused.

`verify-invoices` closes the loop the other way: fiber's decoder reads every string the SDK's encoder wrote, the signed vectors
and 64 invoices generated in the spec (every attribute type and currency, every UTF-8 width, amounts and timestamps of every
size), and must read the values the SDK wrote them from and write each string back unchanged.

## What the tests guarantee

- **Every layer against fiber**, invoice by invoice, both ways, and the SDK's signature over its own digest equal to fiber's.
- **Fixtures written by hand** that survive regenerating the vectors: the hold invoice's string, data, digest and signature,
  the smallest signed invoice, the coder's streams for nothing, one byte and a data table, BIP-350's bech32m strings.
- **One refusal per layer and per field**, each with its exact path and reason: the bech32 forms BIP-350 lists as invalid, the
  human-readable part, the flag, the stream, every molecule rule a reader enforces, every attribute in every wrong size, and
  every signature fault; on the writing side, every field in every wrong form.
- **The bounds**: 16384 bytes of data and one more, both ways; `u64` and `u128` at their maximum and one past; 104 data groups
  and 105.

Coverage of the module is 100% of statements, functions and lines. The branches left are the `?? 0` fallbacks that
`noUncheckedIndexedAccess` requires on indexes always in range. The assertions were checked by breaking the code on purpose:

| Mutation                                                               | Tests that failed |
| ---------------------------------------------------------------------- | ----------------- |
| The range's high rounded instead of truncated                          | 116               |
| A precision of 47 bits instead of 48                                   | 107               |
| The symbol search includes its range's high                            | 93                |
| No pending bit owed when the encoder finishes                          | 74                |
| The range's low computed as `width * below / total`, the product first | 67                |
| Plain bech32's checksum constant                                       | 51                |
| The digest pads with two zero bytes                                    | 47                |
| The string split at the first 1                                        | 38                |
| The digest pads the stream to 8-byte blocks                            | 19                |
| Every count starts at 2                                                | 13                |
| Overlong UTF-8 accepted                                                | 12                |
| The model's total not raised with a count                              | 11                |
| The digest computed without the amount                                 | 8                 |
| An uppercase string read as lowercase, as fiber does                   | 7                 |
| The recovered key not compared with the payee key, as fiber does       | 7                 |
| The decompression limit off by one                                     | 6                 |
| A table field more than the schema's accepted                          | 6                 |
| Only flag 2 refused, the unsigned flag accepted                        | 5                 |
| A lone surrogate written                                               | 5                 |
| Surrogates accepted on read                                            | 4                 |
| Padding bits that are not zero accepted                                | 3                 |
| Leading zeros in the amount accepted                                   | 3                 |
| The decoder reads a repeated attribute type                            | 3                 |
| An unknown hash algorithm byte read as ckb-hash, as fiber does         | 3                 |
| A union id one past the schema accepted                                | 3                 |
| The decoder pads 8 bits more                                           | 2                 |
| The decoder pads 1 bit less                                            | 2                 |
| An empty human-readable part accepted                                  | 2                 |
| The stream not compressed again and compared                           | 2                 |
| A high-S signature accepted                                            | 2                 |
| A 65-byte payee key accepted                                           | 2                 |
| A missing amount written as an invoice without one                     | 2                 |
| The encoder scales the upper half on `low >= half`                     | 1                 |
| A whole group of padding accepted                                      | 1                 |
| A signature with no stream before it accepted                          | 1                 |
| Recovery id 4 accepted                                                 | 1                 |
| The encoder writes a repeated attribute type                           | 1                 |
| The encoder's data limit off by one                                    | 1                 |
| Offsets out of order by one accepted                                   | 1                 |
| A first offset not a multiple of four accepted                         | 1                 |
| `Bytes` longer than its length says accepted                           | 1                 |

Two mutants change nothing observable and are left out: counting the end marker in the model after it is coded, since the
model is never read again, and closing the encoder on `low < quarter` instead of `low <= quarter`, which differs only when
`low` lands exactly on the quarter.
