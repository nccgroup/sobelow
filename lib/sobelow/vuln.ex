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

  alias Sobelow.Utils
  use Sobelow.FindingType

  def get_vulns(root) do
    allowed = @submodules -- Sobelow.get_ignored()

    Enum.each(allowed, fn mod ->
      apply(mod, :run, [root])
    end)
  end

  def print_finding(file, vsn, package, detail, cve \\ "TBA", mod) do
    filename = Utils.normalize_path(file)
    type = "Vuln.#{mod}: Known Vulnerable Dependency - #{package} v#{vsn}"

    case Sobelow.format() do
      "json" ->
        finding = [
          type: type,
          details: detail,
          file: filename,
          cve: cve,
          line: 0
        ]

        Sobelow.log_finding(finding, :high)

      "txt" ->
        Sobelow.log_finding(type, :high)

        Utils.print_custom_finding_metadata(nil, nil, :high, type, [
          "Details: #{detail}",
          "File: #{filename}",
          "CVE: #{cve}"
        ])

      "compact" ->
        Sobelow.Utils.log_compact_finding(type, :high)

      _ ->
        Sobelow.log_finding(type, :high)
    end
  end

  def details() do
    IO.ANSI.Docs.print(@moduledoc)
  end
end
