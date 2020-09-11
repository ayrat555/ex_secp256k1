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
  end
end
