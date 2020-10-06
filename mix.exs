defmodule ExSecp256k1.MixProject do
  use Mix.Project

  def project do
    [
      app: :ex_secp256k1,
      version: "0.1.2",
      elixir: "~> 1.10",
      start_permanent: Mix.env() == :prod,
      compilers: [:rustler] ++ Mix.compilers(),
      rustler_crates: rustler_crates(),
      deps: deps(),
      name: "ExSecp256k1",
      docs: docs(),
      package: package(),
      description: description()
    ]
  end

  defp description do
    """
    Rust Nif that wraps a couple functions from the libsecp256k1 rust library. It only wraps secp256k1 functions used in Ethereum.
    """
  end

  defp package do
    [
      name: :ex_secp256k1,
      maintainers: ["Ayrat Badykov"],
      licenses: ["MIT"],
      links: %{"GitHub" => "https://github.com/ayrat555/ex_secp256k1"},
      files: [
        "mix.exs",
        "native/exsecp256k1/src",
        "native/exsecp256k1/Cargo.toml",
        "lib",
        "LICENSE",
        "README.md",
        "CHANGELOG.md"
      ]
    ]
  end

  defp docs do
    [
      main: "readme",
      extras: [
        "README.md"
      ]
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:rustler, "~> 0.21.1 "},
      {:benchee, "~> 1.0.1", only: :test},
      {:ex_doc, ">= 0.0.0", only: :dev, runtime: false}
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
