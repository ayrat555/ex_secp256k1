defmodule ExSecp256k1 do
  @moduledoc """
  NIF for secp256k1 curve functions.

  It uses https://github.com/paritytech/libsecp256k1
  """
  alias ExSecp256k1.Impl

  @type error :: {:error, atom()}

  @doc """
  Sign a message with the provided private key

  Examples

      iex> message = <<0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2>>
      iex> private_key = <<120, 128, 174, 201, 52, 19, 241, 23, 239, 20, 189, 78, 109, 19, 8, 117, 171, 44, 125, 125, 85, 160, 100, 250, 195, 194, 247, 189, 81, 81, 99, 128>>
      iex> {:ok, {_r_binary, _s_binary, _recovery_id_int}} = ExSecp256k1.sign(message, private_key)
  """
  @spec sign(binary(), binary()) ::
          {:ok, {binary(), binary(), non_neg_integer()}} | error()
  def sign(message, private_key), do: Impl.sign(message, private_key)

  @doc """
  Sign a message with the provided private key. It returns a compact signature

  Examples

      iex> message = <<0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2>>
      iex> private_key = <<120, 128, 174, 201, 52, 19, 241, 23, 239, 20, 189, 78, 109, 19, 8, 117, 171, 44, 125, 125, 85, 160, 100, 250, 195, 194, 247, 189, 81, 81, 99, 128>>
      iex> {:ok, {_signature_bin, _recovery_id_int}} = ExSecp256k1.sign_compact(message, private_key)
  """
  @spec sign_compact(binary(), binary()) :: {:ok, {binary(), non_neg_integer()}} | error()
  def sign_compact(message, private_key), do: Impl.sign_compact(message, private_key)

  @doc """
  Recover public key from a message, its signature and a recovery id

  Examples

      iex> hash = <<218, 245, 167, 121, 174, 151, 47, 151, 33, 151, 48, 61, 123, 87, 71, 70, 199, 239, 131, 234, 218, 192, 242, 121, 26, 210, 61, 185, 46, 76, 142, 83>>
      iex> r = <<40, 239, 97, 52, 11, 217, 57, 188, 33, 149, 254, 83, 117, 103, 134, 96, 3, 225, 161, 93, 60, 113, 255, 99, 225, 89, 6, 32, 170, 99, 98, 118>>
      iex> s = <<103, 203, 233, 216, 153, 127, 118, 26, 236, 183, 3, 48, 75, 56, 0, 204, 245, 85, 201, 243, 220, 100, 33, 75, 41, 127, 177, 150, 106, 59, 109, 131>>
      iex> recovery_id = 0
      iex> {:ok, _public_key_binary} = ExSecp256k1.recover(hash, r, s, recovery_id)
      iex> {:error, :recovery_failure} = ExSecp256k1.recover(hash, r, s, 2)
  """
  @spec recover(binary(), binary(), binary(), non_neg_integer()) :: {:ok, binary()} | error()
  def recover(hash, r, s, recovery_id), do: Impl.recover(hash, r, s, recovery_id)

  @doc """
  Recover public key from a message, its compact signature and a recovery id

  Examples

      iex> hash = <<218, 245, 167, 121, 174, 151, 47, 151, 33, 151, 48, 61, 123, 87, 71, 70, 199, 239, 131, 234, 218, 192, 242, 121, 26, 210, 61, 185, 46, 76, 142, 83>>
      iex> r = <<40, 239, 97, 52, 11, 217, 57, 188, 33, 149, 254, 83, 117, 103, 134, 96, 3, 225, 161, 93, 60, 113, 255, 99, 225, 89, 6, 32, 170, 99, 98, 118>>
      iex> s = <<103, 203, 233, 216, 153, 127, 118, 26, 236, 183, 3, 48, 75, 56, 0, 204, 245, 85, 201, 243, 220, 100, 33, 75, 41, 127, 177, 150, 106, 59, 109, 131>>
      iex> recovery_id = 0
      iex> {:ok, _public_key_binary} = ExSecp256k1.recover_compact(hash, r <> s, recovery_id)
      iex> {:error, :recovery_failure} = ExSecp256k1.recover_compact(hash, r <>  s, 2)
  """
  @spec recover_compact(binary(), binary(), non_neg_integer()) :: {:ok, binary()} | error()
  def recover_compact(hash, signature, recovery_id),
    do: Impl.recover_compact(hash, signature, recovery_id)

  @doc """
  Verify a signature of a message

  Examples

      iex> message = :crypto.strong_rand_bytes(32)
      iex> private_key = :crypto.strong_rand_bytes(32)
      iex> {:ok, {signature, _r}} = ExSecp256k1.sign_compact(message, private_key)
      iex> {:ok, public_key} = ExSecp256k1.create_public_key(private_key)
      iex> :ok = ExSecp256k1.verify(message, signature, public_key)
  """
  @spec verify(binary(), binary(), binary()) :: :ok | error()
  def verify(message, signature, public_key), do: Impl.verify(message, signature, public_key)

  @doc """
  Create a public key from a private key

  Examples

      iex> private_key = :crypto.strong_rand_bytes(32)
      iex> {:ok, _public_key} = ExSecp256k1.create_public_key(private_key)
  """
  @spec create_public_key(binary()) :: {:ok, binary()} | atom()
  def create_public_key(private_key), do: Impl.create_public_key(private_key)

  @doc """
  Tweak public key by adding to it

  Examples

      iex> public_key = <<4, 204, 170, 92, 229, 234, 207, 153, 33, 250, 27, 208, 37, 71, 183, 155, 104, 155, 45, 114, 7, 156, 83, 199, 245, 83, 32, 128, 45, 174, 96, 24, 38, 220, 210, 198, 20, 132, 174, 75, 63, 131, 95, 120, 101, 186, 93, 179, 95, 14, 206, 46, 48, 6, 129, 8, 146, 40, 135, 251, 42, 71, 4, 83, 222>>
      iex> tweak_key = <<50, 8, 92, 222, 223, 155, 132, 50, 53, 227, 114, 79, 88, 11, 248, 24, 239, 76, 236, 39, 195, 198, 112, 133, 224, 41, 65, 138, 91, 47, 111, 43>>
      iex> {:ok, _result} = ExSecp256k1.public_key_tweak_add(public_key, tweak_key)
  """
  @spec public_key_tweak_add(binary(), binary()) :: {:ok, binary()} | atom()
  def public_key_tweak_add(public_key, tweak_key),
    do: Impl.public_key_tweak_add(public_key, tweak_key)

  @doc """
  Tweak public key by multiplying it

  Examples

      iex> public_key = <<4, 204, 170, 92, 229, 234, 207, 153, 33, 250, 27, 208, 37, 71, 183, 155, 104, 155, 45, 114, 7, 156, 83, 199, 245, 83, 32, 128, 45, 174, 96, 24, 38, 220, 210, 198, 20, 132, 174, 75, 63, 131, 95, 120, 101, 186, 93, 179, 95, 14, 206, 46, 48, 6, 129, 8, 146, 40, 135, 251, 42, 71, 4, 83, 222>>
      iex> tweak_key = <<50, 8, 92, 222, 223, 155, 132, 50, 53, 227, 114, 79, 88, 11, 248, 24, 239, 76, 236, 39, 195, 198, 112, 133, 224, 41, 65, 138, 91, 47, 111, 43>>
      iex> {:ok, _result} = ExSecp256k1.public_key_tweak_mult(public_key, tweak_key)
  """
  @spec public_key_tweak_mult(binary(), binary()) :: {:ok, binary()} | atom()
  def public_key_tweak_mult(public_key, tweak_key),
    do: Impl.public_key_tweak_mult(public_key, tweak_key)

  @doc """
  Decompresses public key

  Examples

      iex> public_key = <<2, 204, 170, 92, 229, 234, 207, 153, 33, 250, 27, 208, 37, 71, 183, 155, 104, 155, 45, 114, 7, 156, 83, 199, 245, 83, 32, 128, 45, 174, 96, 24, 38>>
      iex> {:ok, _result} = ExSecp256k1.public_key_decompress(public_key)
  """
  @spec public_key_decompress(binary()) :: {:ok, binary()} | atom()
  def public_key_decompress(public_key), do: Impl.public_key_decompress(public_key)

  @doc """
  Compresses public key

  Examples

      iex> public_key = <<4, 204, 170, 92, 229, 234, 207, 153, 33, 250, 27, 208, 37, 71, 183, 155, 104, 155, 45, 114, 7, 156, 83, 199, 245, 83, 32, 128, 45, 174, 96, 24, 38, 220, 210, 198, 20, 132, 174, 75, 63, 131, 95, 120, 101, 186, 93, 179, 95, 14, 206, 46, 48, 6, 129, 8, 146, 40, 135, 251, 42, 71, 4, 83, 222>>
      iex> {:ok, _result} = ExSecp256k1.public_key_compress(public_key)
  """
  @spec public_key_compress(binary()) :: {:ok, binary()} | atom()
  def public_key_compress(public_key), do: Impl.public_key_compress(public_key)

  @doc """
  Tweak public key by adding to it

  Examples

      iex> private_key = <<72, 91, 33, 135, 186, 13, 21, 144, 75, 36, 27, 203, 157, 203, 177, 166, 86, 92, 151, 137, 148, 205, 234, 174, 192, 12, 9, 227, 208, 173, 74, 69>>
      iex> {:ok, _result} = ExSecp256k1.private_key_tweak_add(private_key, private_key)
  """
  @spec private_key_tweak_add(binary(), binary()) :: {:ok, binary()} | atom()
  def private_key_tweak_add(private_key, tweak_key),
    do: Impl.private_key_tweak_add(private_key, tweak_key)

  @doc """
  Tweak private key by multiplying it

  Examples

      iex> private_key = <<72, 91, 33, 135, 186, 13, 21, 144, 75, 36, 27, 203, 157, 203, 177, 166, 86, 92, 151, 137, 148, 205, 234, 174, 192, 12, 9, 227, 208, 173, 74, 69>>
      iex> {:ok, _result} = ExSecp256k1.private_key_tweak_mult(private_key, private_key)
  """
  @spec private_key_tweak_mult(binary(), binary()) :: {:ok, binary()} | atom()
  def private_key_tweak_mult(private_key, tweak_key),
    do: Impl.private_key_tweak_mult(private_key, tweak_key)
end
