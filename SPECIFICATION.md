# Binary Output Script Descriptor (BOSD) Specification

Author: Trey Del Bonis <trey@alpenlabs.io>

## Motivation

There doesn't exist any general standard way to encode arbitrary relay-safe
outputs. But we want to support creating a wide range of output types (any address
and also `OP_RETURN`s) in use cases such as layer 2's withdrawal outputs.

### Design Requirements

So looking at these constraints we can say that we have these requirements:

- must not involve error correction/detection overheads
- must not include network-related data that's redundant based on context
- is a bijection with some sane "relay-safe subset" of `ScriptBuf`s,
  corresponding to both textual addresses and including `OP_RETURN`s

## Proposal

I propose a byte-based format to capture these needs. This would serve to be
more like a "output spec" rather than an "address" as it more specifically
intends to describe the data that is wanted on output rather than something
passed around as a general destination.

The structure consists of:

- 1-byte tag representing a type ID.
- Arbitrary-length cryptographic payload (although practically bounded to like
  80 bytes).

We assume that we're parsing a descriptor from a container so that we don't need
to explicitly specify the length of the payload and can assume it to be "the rest
of the buffer". If necessary, the length should include the full length of the
buffer (including the type tag) to reserve the possibility for multi-byte tags
in a future iteration of this spec.

A strength of this approach is that the validation requirements are minimal. To
parse a descriptor, we only have to check that the type ID is in bounds and that
the length of the payload is acceptable for that type ID. We don't actually
have to look at the payload and consider if it's structurally valid given the
context.

| Type | Payload Length(s) | Payload Interpretation | Spend Type    | Mainnet Address Prefix |
| ---- | ----------------- | ---------------------- | ------------- | ---------------------- |
| 0    | ..=80             | `OP_RETURN` payload    | (N/A)         | (N/A)                  |
| 1    | 20                | pubkey hash            | P2PKH         | `1...`                 |
| 2    | 20                | script hash            | P2SH          | `3...`                 |
| 3    | 20, 32            | SegWit v0 hash         | P2WPKH, P2WSH | `bc1q...`              |
| 4    | 32                | SegWit v1 public key   | P2TR          | `bc1p...`              |

Our goal here is in part to be a projection of the different address formats.
So as a result we have the two legacy address formats as their own types, and
the two newer SegWit address types as their own types. We could have focused
more on _the spend types_ and given P2WPKH and P2WSH each their own type IDs,
however this would have been at odds with how these outputs are represented in
transactions and in the address encoding.

## Upgradability

If we introduce new types of outputs as standard output types, then we can add
another type ID. The "compliance version" of an implementation of this spec can
be specified by the highest value of type ID it supports.

We would be able to directly construct a `ScriptBuf` to use as a scriptPubKey
from a descriptor, without having to convert it to an address first. For any
address there is exactly one unique way to represent it as a descriptor.

In the event that the `OP_RETURN` payload limit is increased, then we would want
to support that. In that scenario, we will introduce a new type ID specifically
for the range between the currently-supported limit and the new limit. So a
type 0 desc with a 81 byte payload would still be invalid. And a type k with a
79 byte payload would similarly be invalid.

## Examples

- `034d6151263d87371392bb1b60405392c5ba2e3297` ↔ bc1qf4s4zf3asum38y4mrdsyq5ujckazuv5hczg979
- `041234123412341234123412341234123412341234123412341234123412341234` ↔ bc1pzg6pydqjxsfrgy35zg6pydqjxsfrgy35zg6pydqjxsfrgy35zg6qf6d5se
- `00deadbeefcafebabe` ↔ `RETURN PUSHDATA(deadbeefcafebabe)`

## Textual Representation

Ideally we wouldn't represent instances of this format textually. The most
naive way to present it is as hex, but this is maybe somewhat awkward to use.

If in a context where a particular network can be determined, we can just
generate an address for most descriptors, but `OP_RETURN` outputs don't have an
address. For those cases, we can fall back to using a "fake" bech32 address
with a `return` HRP.

- `return1m6kmam72l6atudcj907` ↔ `00deadbeefcafebabe`

## Prior Art

> [!NOTE]
> Using terms from the `bitcoin` crate.

### `Address` + something extra for `OP_RETURN`

The main issue with this is that it's inefficient since it involves linear
overhead for the error correction, plus some constant overhead for the network
tag and other framing bytes (like `1` in bech32). There's also some debate that
could be had over how `OP_RETURN` ought to work here.

`Address` is a user-facing type that represents a decoded form of what's
represented by _addresses_ specifically, but we're looking for something that
represents that gets included in transactions.

We would _like_ to use something like `AddressData`, but this is more of an
internal type and doesn't have any serializable representation.

### Use `ScriptBuf` directly

This permits non-standard outputs which aren't relay-safe. We want to constrain
ourselves to standard outputs as that could result in layer 2's operators having
a hard time getting a non-standard transaction included. This could be seen as
a griefing attack.

We could constrain ourselves to only permit a subset of `ScriptBuf`s, but this
is messy and feels like it runs afoul of the "parse don't validate" principle
that Rust encourages.

## Questions

- What if we remove standard types and we need to remove types from the table?
  This seems unlikely as it would invalidate established use cases.

## LICENSE

This specification is licensed under the [CC0 public domain](https://creativecommons.org/public-domain/cc0/)
license.
