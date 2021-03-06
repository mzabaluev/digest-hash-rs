# Stable cryptographic hashing for data structures

This crate provides traits and utilities to facilitate stable
cryptographic-grade hashing of data structures, interoperable with
the cryptographic hash functions that conform to the API defined in
crate [digest](https://crates.io/crates/digest).

## Motivation

Considering that more general-purpose traits and frameworks are already
available for serializing and hashing application data, a question arises
whether this separate trait system is useful. The key concern that the
provided functionality tries to address is suitability for cryptographic
applications.

### Why not `std::hash::Hash`?

The standard traits `Hash` and `Hasher` are widely used by applications and
`Hash` implementations are easily derivable. However, these traits are
designed to support in-process hash table collections and as such, they do
not facilitate machine- and language-independent hashing. It's freely
allowed to hash `isize`/`usize` values, and representation
of many data types is considered an implementation detail: for example,
the `Hash` implementation for a byte slice is both dependent on the target
architecture and different from feeding the slice content in sequence to an
equivalent `Hasher`.

### What's wrong with Serde?

[Serde](https://serde.rs/) is a full-fledged data serialization framework
designed to be universally applicable. It is both widely used and recommended
as the way to implement serialization for data types in the Rust ecosystem.
Serde's design is amenable to implementing well-defined, cross-platform
data representations. However, because it's a general-purpose framework,
an implementation of `Serializer` suitable for cryptographic data signing
and validation has to make data representation choices to accommodate
Serde's universal data model, or come up with a strategy to handle unwanted
or unsupported features should any `Serialize` implementation make
use of them.
Configuration of these choices is decoupled from type-specific `Serialize`
implementations.

Consider this scenario:

```rust
// crate a
#[derive(Serialize)]
pub struct A {
    foo: char
}
```

```rust
// crate b
extern crate a;
#[derive(Serialize)]
pub struct B {
    bar: a::A
}
```

An application wishing to calculate a hash of `B` through the hypothetical
`Serializer` backend would have to be aware that the choice of how to hash
the inner `char` would affect the result, even though the `char` is an
implementation detail of `A` and may be not easily visible to the
application developer: she'd have to either look at the source of `a`
if that is available, or find it in a serialization dump of `A` or `B` made in
a human-readable format.

That said, a Serde backend to serialize arbitrary data structures for
purposes of cryptographic hashing may be eventually provided, and its
implementation can make use of the facilities provided by this crate.

### Unopinionated hashing API

The traits and their implementations provided by this crate aim for a
middle ground: they enable platform-independent digest calculation, while
avoiding any implicit data representation choices. For example, hashing
of IP addresses is not available out of the box, because the representation
format may, in principle, use various byte orders, a way to mix IPv4 and IPv6
is not set in stone, and the representation of IPv6 addresses can make
different choices about the constituent data units and their endianness.
Some commonly used representation choices are made available with helper
functions defined in module `personality`.

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
