defmodule ExSecp256k1.Impl do
  @moduledoc false

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
