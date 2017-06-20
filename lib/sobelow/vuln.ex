defmodule Sobelow.Vuln do
  @moduledoc """
  # Known Vulnerable Dependencies

  An application with known vulnerabilities is more easily subjected
  to automated or targeted attacks.

  Known Vulnerable checks can be ignored with the following command:

      $ mix sobelow -i Vuln
  """
  alias Sobelow.Utils
  @submodules [Sobelow.Vuln.PlugNull, Sobelow.Vuln.CookieRCE, Sobelow.Vuln.HeaderInject, Sobelow.Vuln.Redirect]
  use Sobelow.Finding

  def get_vulns(root) do
    allowed = @submodules -- Sobelow.get_ignored()

    Enum.each allowed, fn mod ->
      apply(mod, :run, [root])
    end
  end

  def print_finding(vsn, package, detail, cve \\ "TBA") do
    type = "Known Vulnerable Dependency - #{package} v#{vsn}"
    case Sobelow.format() do
      "json" ->
        finding = [type: type]
        Sobelow.log_finding(finding, :high)
      _ ->
        Sobelow.log_finding(type, :high)
        IO.puts IO.ANSI.red() <> type <> IO.ANSI.reset()
        if Sobelow.get_env(:with_code), do: print_detail(detail, cve)
        IO.puts "\n-----------------------------------------------\n"
    end
  end

  defp print_detail(detail, cve) do
    IO.puts("Details: #{detail}")
    IO.puts("CVE: #{cve}")
  end
end