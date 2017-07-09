defmodule Sobelow.Vuln.HeaderInject do
  alias Sobelow.Utils
  alias Sobelow.Vuln
  use Sobelow.Finding

  @vuln_vsn ["<=1.3.4 and >=1.3.0", "<=1.2.4 and >=1.2.0", "<=1.1.8 and >=1.1.0", "<=1.0.5"]

  def run(root) do
    plug_conf = root <> "/deps/plug/mix.exs"

    if File.exists?(plug_conf) do
      vsn = Utils.get_version(plug_conf)

      case Version.parse(vsn) do
        {:ok, vsn} ->
          if Enum.any?(@vuln_vsn, fn v -> Version.match?(vsn, v) end) do
            Vuln.print_finding(vsn, "Plug", "Header Injection")
          end
        _ -> nil
      end
    end

  end

  def get_details() do
    Sobelow.Vuln.details()
  end
end
