defmodule Sobelow.Vuln.PlugNull do
  alias Sobelow.Utils
  alias Sobelow.Vuln
  use Sobelow.Finding

  @vuln_vsn ~w(1.3.1 1.3.0 1.2.2 1.2.1 1.2.0 1.1.6 1.1.5 1.1.4 1.1.3 1.1.2 1.1.1 1.1.0 1.0.3 1.0.2 1.0.1 1.0.0)

  def run(root) do
    plug_conf = root <> "/deps/plug/mix.exs"

    if File.exists?(plug_conf) do
      vsn = Utils.get_version(plug_conf)

      if Enum.member?(@vuln_vsn, vsn) do
        Vuln.print_finding(
          vsn,
          "Plug",
          "Null Byte Injection in Plug.Static",
          "CVE-2017-1000052",
          plug_conf
        )
      end
    end
  end

  def details() do
    Sobelow.Vuln.details()
  end
end
