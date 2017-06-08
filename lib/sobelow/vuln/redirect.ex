defmodule Sobelow.Vuln.Redirect do
  alias Sobelow.Config
  alias Sobelow.Utils
  alias Sobelow.Vuln
  use Sobelow.Finding

  @vuln_vsn ~w(1.0.0 1.0.1 1.0.2 1.0.3 1.0.4 1.1.0 1.1.1 1.1.2 1.1.3 1.1.4 1.1.5 1.1.6 1.2.0 1.2.1 1.3.0-rc.0)

  def run(root) do
    plug_conf = root <> "/deps/phoenix/mix.exs"
    if File.exists?(plug_conf) do
      vsn = Utils.get_version(plug_conf)

      if Enum.member?(@vuln_vsn, vsn) do
        Vuln.print_finding(vsn, "Phoenix", "Arbitrary URL Redirect")
      end
    end
  end

  def print_finding(vsn) do
    IO.puts IO.ANSI.red() <> "Arbitrary URL Redirect" <> IO.ANSI.reset()
    if Sobelow.get_env(:with_code), do: IO.puts("Phoenix Version: #{vsn}")
    IO.puts "\n-----------------------------------------------\n"
  end

  def get_details() do
    Sobelow.Vuln.details()
  end
end