defmodule Sobelow.Vuln.HeaderInject do
  alias Sobelow.Config
  alias Sobelow.Vuln

  @uid 25
  @finding_type "Vuln.HeaderInject: Known Vulnerable Dependency - Update Plug"

  use Sobelow.Finding

  @vuln_vsn ["<=1.3.4 and >=1.3.0", "<=1.2.4 and >=1.2.0", "<=1.1.8 and >=1.1.0", "<=1.0.5"]

  def run(root) do
    plug_conf = root <> "/deps/plug/mix.exs"

    if File.exists?(plug_conf) do
      vsn = Config.get_version(plug_conf)

      case Version.parse(vsn) do
        {:ok, vsn} ->
          if Enum.any?(@vuln_vsn, fn v -> Version.match?(vsn, v) end) do
            Vuln.print_finding(plug_conf, vsn, "Plug", "Header Injection", "HeaderInject")
          end

        _ ->
          nil
      end
    end
  end

  def details() do
    Sobelow.Vuln.details()
  end
end
