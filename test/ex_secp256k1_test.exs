defmodule ExSecp256k1Test do
  use ExUnit.Case
  doctest ExSecp256k1

  describe "sign/2" do
    setup do
      private_key =
        "8da4ef21b864d2cc526dbdb2a120bd2874c36c9d0a1fb7f8c63d7f7a8b41de8f"
        |> String.upcase()
        |> Base.decode16!()

      message =
        <<0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 2>>

      {:ok, %{private_key: private_key, message: message}}
    end

    test "correctly signs message with the provided private key", %{
      private_key: private_key,
      message: message
    } do
      assert {
               :ok,
               {<<73, 102, 23, 43, 29, 88, 149, 68, 77, 65, 248, 57, 200, 155, 43, 249, 154, 95,
                  100, 185, 121, 244, 84, 178, 159, 90, 254, 45, 27, 177, 221, 218>>,
                <<21, 214, 167, 20, 61, 86, 189, 86, 241, 39, 239, 70, 71, 66, 201, 140, 21, 23,
                  206, 201, 129, 255, 24, 20, 160, 152, 36, 114, 115, 245, 33, 208>>, 1}
             } = ExSecp256k1.sign(message, private_key)
    end

    test "fails if private key size < 32 bytes", %{message: message} do
      assert {:error, :wrong_private_key_size} = ExSecp256k1.sign(message, <<1>>)
    end

    test "fails if message size < 32 bytes", %{private_key: private_key} do
      assert {:error, :wrong_message_size} = ExSecp256k1.sign(<<1>>, private_key)
    end

    test "fails if private_key is not binary", %{message: message} do
      assert {:error, :private_key_not_binary} = ExSecp256k1.sign(message, nil)
    end

    test "fails if message is not binary", %{private_key: private_key} do
      assert {:error, :message_not_binary} = ExSecp256k1.sign(10, private_key)
    end

    @tag :perf
    @tag timeout: 300_000
    test "sequential performance test", %{private_key: private_key, message: message} do
      Benchee.run(
        %{
          "ex_secp256k1 sign seq" => fn ->
            ExSecp256k1.sign(message, private_key)
          end
        },
        time: 100,
        memory_time: 10
      )
    end

    @tag :perf
    @tag timeout: 300_000
    test "parallel performance test", %{private_key: private_key, message: message} do
      Benchee.run(
        %{
          "ex_secp256k1 sign par" => fn ->
            ExSecp256k1.sign(message, private_key)
          end
        },
        time: 100,
        memory_time: 10,
        parallel: 4
      )
    end
  end

  describe "sign_compact/2" do
    setup do
      private_key =
        "8da4ef21b864d2cc526dbdb2a120bd2874c36c9d0a1fb7f8c63d7f7a8b41de8f"
        |> String.upcase()
        |> Base.decode16!()

      message =
        <<0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 2>>

      {:ok, %{private_key: private_key, message: message}}
    end

    test "returns signature in the compact form", %{
      private_key: private_key,
      message: message
    } do
      assert {:ok,
              {<<73, 102, 23, 43, 29, 88, 149, 68, 77, 65, 248, 57, 200, 155, 43, 249, 154, 95,
                 100, 185, 121, 244, 84, 178, 159, 90, 254, 45, 27, 177, 221, 218, 21, 214, 167,
                 20, 61, 86, 189, 86, 241, 39, 239, 70, 71, 66, 201, 140, 21, 23, 206, 201, 129,
                 255, 24, 20, 160, 152, 36, 114, 115, 245, 33, 208>>,
               1}} = ExSecp256k1.sign_compact(message, private_key)
    end

    @tag :perf
    @tag timeout: 300_000
    test "sequential performance test", %{private_key: private_key, message: message} do
      Benchee.run(
        %{
          "ex_secp256k1 sign_compact seq" => fn ->
            ExSecp256k1.sign_compact(message, private_key)
          end
        },
        time: 100,
        memory_time: 10
      )
    end

    @tag :perf
    @tag timeout: 300_000
    test "parallel performance test", %{private_key: private_key, message: message} do
      Benchee.run(
        %{
          "ex_secp256k1 sign_compact par" => fn ->
            ExSecp256k1.sign_compact(message, private_key)
          end
        },
        time: 100,
        memory_time: 10,
        parallel: 4
      )
    end
  end

  describe "recover/4" do
    setup do
      hash =
        <<218, 245, 167, 121, 174, 151, 47, 151, 33, 151, 48, 61, 123, 87, 71, 70, 199, 239, 131,
          234, 218, 192, 242, 121, 26, 210, 61, 185, 46, 76, 142, 83>>

      r =
        <<40, 239, 97, 52, 11, 217, 57, 188, 33, 149, 254, 83, 117, 103, 134, 96, 3, 225, 161, 93,
          60, 113, 255, 99, 225, 89, 6, 32, 170, 99, 98, 118>>

      s =
        <<103, 203, 233, 216, 153, 127, 118, 26, 236, 183, 3, 48, 75, 56, 0, 204, 245, 85, 201,
          243, 220, 100, 33, 75, 41, 127, 177, 150, 106, 59, 109, 131>>

      recovery_id = 0

      {:ok,
       %{
         hash: hash,
         r: r,
         s: s,
         recovery_id: recovery_id
       }}
    end

    test "recovers public key", %{
      hash: hash,
      r: r,
      s: s,
      recovery_id: recovery_id
    } do
      assert {:ok,
              <<4, 75, 194, 163, 18, 101, 21, 63, 7, 231, 14, 11, 171, 8, 114, 78, 107, 133, 226,
                23, 248, 205, 98, 140, 235, 98, 151, 66, 71, 187, 73, 51, 130, 206, 40, 202, 183,
                154, 215, 17, 158, 225, 173, 62, 188, 219, 152, 161, 104, 5, 33, 21, 48, 236, 198,
                207, 239, 161, 184, 142, 109, 255, 153, 35,
                42>>} = ExSecp256k1.recover(hash, r, s, recovery_id)
    end

    test "fails to recover if hash < 32 bytes", %{r: r, s: s, recovery_id: recovery_id} do
      assert {:error, :wrong_hash_size} = ExSecp256k1.recover(<<1>>, r, s, recovery_id)
    end

    test "fails to recover if r < 32 bytes", %{hash: hash, s: s, recovery_id: recovery_id} do
      assert {:error, :wrong_r_size} = ExSecp256k1.recover(hash, <<1>>, s, recovery_id)
    end

    test "fails to recover if s < 32 bytes", %{hash: hash, r: r, recovery_id: recovery_id} do
      assert {:error, :wrong_s_size} = ExSecp256k1.recover(hash, r, <<1>>, recovery_id)
    end

    test "fails to recover if hash is not binary", %{r: r, s: s, recovery_id: recovery_id} do
      assert {:error, :hash_not_binary} = ExSecp256k1.recover(nil, r, s, recovery_id)
    end

    test "fails to recover if r is not binary", %{hash: hash, s: s, recovery_id: recovery_id} do
      assert {:error, :r_not_binary} = ExSecp256k1.recover(hash, 99, s, recovery_id)
    end

    test "fails to recover if s is not binary", %{hash: hash, r: r, recovery_id: recovery_id} do
      assert {:error, :s_not_binary} = ExSecp256k1.recover(hash, r, %{}, recovery_id)
    end

    test "fails to recover if recover_id is not number", %{hash: hash, r: r, s: s} do
      assert {:error, :recovery_id_not_u8} = ExSecp256k1.recover(hash, r, s, "")
    end

    test "fails to recover if recover_id is invalid", %{hash: hash, r: r, s: s} do
      assert {:error, :invalid_recovery_id} = ExSecp256k1.recover(hash, r, s, 100)
    end

    test "fails to recover unrecoverable data", %{hash: hash, r: r, s: s} do
      assert {:error, :recovery_failure} = ExSecp256k1.recover(hash, r, s, 2)
    end

    @tag :perf
    @tag timeout: 300_000
    test "sequential performance test", %{
      hash: hash,
      r: r,
      s: s,
      recovery_id: recovery_id
    } do
      Benchee.run(
        %{
          "ex_secp256k1 recover seq" => fn ->
            ExSecp256k1.recover(hash, r, s, recovery_id)
          end
        },
        time: 100,
        memory_time: 10
      )
    end

    @tag :perf
    @tag timeout: 300_000
    test "parallel performance test", %{
      hash: hash,
      r: r,
      s: s,
      recovery_id: recovery_id
    } do
      Benchee.run(
        %{
          "ex_secp256k1 recover par" => fn ->
            ExSecp256k1.recover(hash, r, s, recovery_id)
          end
        },
        time: 100,
        memory_time: 10,
        parallel: 4
      )
    end
  end

  describe "create_public_key/1" do
    test "creates public key from private key" do
      private_key =
        <<120, 128, 174, 201, 52, 19, 241, 23, 239, 20, 189, 78, 109, 19, 8, 117, 171, 44, 125,
          125, 85, 160, 100, 250, 195, 194, 247, 189, 81, 81, 99, 128>>

      assert {:ok,
              <<4, 196, 192, 12, 151, 91, 46, 136, 104, 28, 140, 147, 175, 203, 109, 123, 247,
                168, 3, 74, 46, 67, 92, 219, 154, 218, 144, 135, 114, 76, 12, 140, 213, 136, 29,
                101, 44, 225, 99, 58, 116, 118, 3, 199, 153, 99, 106, 231, 21, 184, 191, 183, 239,
                161, 155, 87, 19, 83, 37, 22, 168, 71, 124, 27,
                172>>} = ExSecp256k1.create_public_key(private_key)
    end

    test "fails to generate public key if private key is not 32 bytes" do
      assert {:error, :wrong_private_key_size} = ExSecp256k1.create_public_key(<<1>>)
    end

    test "fails to generate public key if private key is not binary" do
      assert {:error, :private_key_not_binary} = ExSecp256k1.create_public_key(nil)
    end

    @tag :perf
    @tag timeout: 300_000
    test "sequential performance test" do
      private_key = :crypto.strong_rand_bytes(32)

      Benchee.run(
        %{
          "ex_secp256k1 create_public_key seq" => fn ->
            ExSecp256k1.create_public_key(private_key)
          end
        },
        time: 100,
        memory_time: 10
      )
    end

    @tag :perf
    @tag timeout: 300_000
    test "parallel performance test" do
      private_key = :crypto.strong_rand_bytes(32)

      Benchee.run(
        %{
          "ex_secp256k1 create_public_key par" => fn ->
            ExSecp256k1.create_public_key(private_key)
          end
        },
        time: 100,
        memory_time: 10,
        parallel: 6
      )
    end
  end
end
