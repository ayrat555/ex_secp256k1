# ExSecp256k1

[![Hex.pm](https://img.shields.io/hexpm/v/ex_secp256k1.svg)](https://hex.pm/packages/ex_secp256k1)
[![Hex.pm](https://img.shields.io/hexpm/dt/ex_secp256k1.svg)](https://hex.pm/packages/ex_secp256k1)
[![Hex.pm](https://img.shields.io/hexpm/l/ex_secp256k1.svg)](https://hex.pm/packages/ex_secp256k1)
[![Github.com](https://img.shields.io/github/last-commit/omgnetwork/ex_secp256k1.svg)](https://github.com/omgnetwork/ex_secp256k1)

NIF for secp256k1 curve functions.

It wraps functions from the [libsecp256k1](https://github.com/paritytech/libsecp256k1) Rust library.

## Installation

`ex_secp256k1` requires Rust to be installed.

The package can be installed by adding `ex_secp256k1` to your list of
dependencies in `mix.exs`:

```elixir
  [
    {:ex_secp256k1, "~> 0.6"}
  ]
```


### Force compilation

This library includes pre-compiled binaries for the native Rust code. If you 
want to force-compile the Rust code, you can add the following configuration
to your application:

```
config :rustler_precompiled, :force_build, ex_secp256k1: true
```

You also need to add Rusler to your dependencies:

```
def deps do
  [
    {:ex_secp256k1, "~> 0.6.0"},
    {:rustler, ">= 0.0.0", optional: true}
  ]
end
```

## Usage

The docs can be found at [https://hexdocs.pm/ex_secp256k1](https://hexdocs.pm/ex_secp256k1).

## Contributing

1. [Fork it!](https://github.com/ayrat555/ex_secp256k1)
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request
