defmodule ExSecp256k1 do
  use Rustler, otp_app: :ex_secp256k1, crate: "exsecp256k1"

  def sign(_message, _private_key), do: :erlang.nif_error(:nif_not_loaded)

  def ec_recover(_hash, _r, _s, _recovery_id), do: :erlang.nif_error(:nif_not_loaded)
end
