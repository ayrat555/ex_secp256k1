defmodule ExSecp256k1.MixProject do
  use Mix.Project

  def project do
    [
      app: :ex_secp256k1,
      version: "0.1.0",
      elixir: "~> 1.10",
      start_permanent: Mix.env() == :prod,
      compilers: [:rustler] ++ Mix.compilers(),
      rustler_crates: rustler_crates(),
      deps: deps()
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:rustler, "~> 0.21.1 "}
    ]
  end

  defp rustler_crates do
    [
      exsecp256k1: [
        path: "native/exsecp256k1",
        mode: rustc_mode(Mix.env())
      ]
    ]
  end

  defp rustc_mode(:prod), do: :release
  defp rustc_mode(_), do: :debug
end
