defmodule ExSecp256k1Test do
  use ExUnit.Case
  doctest ExSecp256k1

  test "greets the world" do
    assert ExSecp256k1.hello() == :world
  end
end
