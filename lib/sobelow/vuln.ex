defmodule Sobelow.Vuln do
  @moduledoc """
  # Known Vulnerable Dependencies

  An application with known vulnerabilities is more easily subjected
  to automated or targeted attacks.

  Known Vulnerable checks can be ignored with the following command:

      $ mix sobelow -i Vuln
  """
  @submodules [
    Sobelow.Vuln.PlugNull,
    Sobelow.Vuln.CookieRCE,
    Sobelow.Vuln.HeaderInject,
    Sobelow.Vuln.Redirect,
    Sobelow.Vuln.Coherence,
    Sobelow.Vuln.Ecto
  ]
  use Sobelow.FindingType

  def get_vulns(root) do
    allowed = @submodules -- Sobelow.get_ignored()

    Enum.each(allowed, fn mod ->
      apply(mod, :run, [root])
    end)
  end

  def print_finding(vsn, package, detail, cve \\ "TBA") do
    type = "Known Vulnerable Dependency - #{package} v#{vsn}"

    case Sobelow.format() do
      "json" ->
        finding = [type: type, details: detail, cve: cve]
        Sobelow.log_finding(finding, :high)

      "txt" ->
        Sobelow.log_finding(type, :high)
        IO.puts(IO.ANSI.red() <> type <> IO.ANSI.reset())
        if Sobelow.get_env(:verbose), do: print_detail(detail, cve)
        IO.puts("\n-----------------------------------------------\n")

      "compact" ->
        Sobelow.Utils.log_compact_finding(type, :high)

      _ ->
        Sobelow.log_finding(type, :high)
    end
  end

  defp print_detail(detail, cve) do
    IO.puts("Details: #{detail}")
    IO.puts("CVE: #{cve}")
  end

  def details() do
    IO.ANSI.Docs.print(@moduledoc)
  end
end
