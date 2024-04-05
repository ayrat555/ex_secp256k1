defmodule ExSecp256k1.Impl do
  @moduledoc false

  version = Mix.Project.config()[:version]

  use RustlerPrecompiled,
    otp_app: :ex_secp256k1,
    crate: :ex_secp256k1,
    base_url: "https://github.com/ayrat555/ex_secp256k1/releases/download/v#{version}",
    force_build: System.get_env("RUSTLER_BUILD") in ["1", "true"],
    targets: Enum.uniq(["x86_64-unknown-freebsd" | RustlerPrecompiled.Config.default_targets()]),
    nif_versions: ["2.15", "2.16"],
    version: version

  def sign(_message, _private_key), do: :erlang.nif_error(:nif_not_loaded)

  def sign_compact(_message, _private_key), do: :erlang.nif_error(:nif_not_loaded)

  def recover(_hash, _r, _s, _recovery_id), do: :erlang.nif_error(:nif_not_loaded)

  def recover_compact(_hash, _signature, _recovery_id), do: :erlang.nif_error(:nif_not_loaded)

  def verify(_message, _signature, _public_key), do: :erlang.nif_error(:nif_not_loaded)

  def create_public_key(_private_key), do: :erlang.nif_error(:nif_not_loaded)

  def public_key_tweak_add(_public_key, _tweak_key), do: :erlang.nif_error(:nif_not_loaded)

  def public_key_tweak_mult(_public_key, _tweak_key), do: :erlang.nif_error(:nif_not_loaded)

  def public_key_decompress(_public_key), do: :erlang.nif_error(:nif_not_loaded)

  def public_key_compress(_public_key), do: :erlang.nif_error(:nif_not_loaded)

  def private_key_tweak_add(_private_key, _tweak_key), do: :erlang.nif_error(:nif_not_loaded)

  def private_key_tweak_mult(_private_key, _tweak_key), do: :erlang.nif_error(:nif_not_loaded)
end
