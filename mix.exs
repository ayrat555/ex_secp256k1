defmodule ExSecp256k1.MixProject do
  use Mix.Project

  @source_url "https://github.com/omgnetwork/ex_secp256k1"

  def project do
    [
      app: :ex_secp256k1,
      name: "ExSecp256k1",
      version: "0.2.0",
      elixir: "~> 1.10",
      start_permanent: Mix.env() == :prod,
      compilers: Mix.compilers(),
      deps: deps(),
      docs: docs(),
      package: package(),
      description: description()
    ]
  end

  defp description do
    """
    Rust Nif that wraps a couple functions from the libsecp256k1 Rust library.
    It only wraps secp256k1 functions used in Ethereum.
    """
  end

  defp package do
    [
      name: :ex_secp256k1,
      maintainers: ["Ayrat Badykov"],
      licenses: ["MIT"],
      links: %{
        "Changelog" => "#{@source_url}/blog/master/CHANGELOG.md",
        "GitHub" => @source_url
      },
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
      source_url: @source_url,
      extras: [
        "CHANGELOG.md",
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
      {:rustler, "~> 0.22"},
      {:benchee, "~> 1.0.1", only: :test},
      {:ex_doc, ">= 0.0.0", only: :dev, runtime: false}
    ]
  end
end
