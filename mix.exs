defmodule Sobelow.Mixfile do
  use Mix.Project

  @source_url "https://github.com/nccgroup/sobelow"
  @version "0.10.6"

  def project do
    [
      app: :sobelow,
      version: @version,
      elixir: "~> 1.4",
      build_embedded: Mix.env() == :prod,
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      package: package(),
      description: "Security-focused static analysis for the Phoenix framework",
      name: "Sobelow",
      homepage_url: "https://sobelow.io",
      docs: docs()
    ]
  end

  def application do
    [extra_applications: [:logger, :eex, :inets]]
  end

  defp deps do
    [{:ex_doc, "~> 0.20", only: :dev}]
  end

  defp package() do
    [
      licenses: ["Apache 2"],
      maintainers: ["Griffin Byatt"],
      links: %{
        "Changelog" => "#{@source_url}/blob/master/CHANGELOG.md",
        "GitHub" => @source_url
      }
    ]
  end

  defp docs() do
    [
      main: "readme",
      source_url: @source_url,
      source_ref: "v#{@version}",
      extras: ["README.md", "CHANGELOG.md"]
    ]
  end
end
