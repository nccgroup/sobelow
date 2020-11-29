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

  alias Sobelow.{Finding, Utils, Print}
  use Sobelow.FindingType

  def get_vulns(root) do
    allowed = @submodules -- Sobelow.get_ignored()

    Enum.each(allowed, fn mod ->
      apply(mod, :run, [root])
    end)
  end

  def print_finding(file, vsn, package, detail, cve \\ "TBA", mod) do
    type = "Vuln.#{mod}: Known Vulnerable Dependency - #{package} v#{vsn}"

    finding =
      %Finding{
        type: type,
        filename: Utils.normalize_path(file),
        fun_source: nil,
        vuln_source: nil,
        vuln_line_no: 0,
        vuln_col_no: 0,
        confidence: :high
      }
      |> Finding.fetch_fingerprint()

    case Sobelow.format() do
      "json" ->
        json_finding = [
          type: finding.type,
          details: detail,
          file: finding.filename,
          cve: cve,
          line: 0
        ]

        Sobelow.log_finding(json_finding, finding)

      "txt" ->
        Sobelow.log_finding(finding)

        Print.print_custom_finding_metadata(finding, [
          "Details: #{detail}",
          "File: #{finding.filename}",
          "CVE: #{cve}"
        ])

      "compact" ->
        Print.log_compact_finding(finding)

      _ ->
        Sobelow.log_finding(finding)
    end
  end

  def details() do
    @moduledoc
  end
end
