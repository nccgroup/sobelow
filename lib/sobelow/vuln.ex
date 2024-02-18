defmodule Sobelow.Vuln do
  @moduledoc """
  # Known Vulnerable Dependencies

  An application with known vulnerabilities is more easily subjected
  to automated or targeted attacks.

  If you wish to learn more about the specific vulnerabilities
  found within the Known Vulnerable Dependencies category, you may run the
  following commands to find out more:

            $ mix sobelow -d Vuln.PlugNull
            $ mix sobelow -d Vuln.CookieRCE
            $ mix sobelow -d Vuln.HeaderInject
            $ mix sobelow -d Vuln.Redirect
            $ mix sobelow -d Vuln.Coherence
            $ mix sobelow -d Vuln.Ecto

  Known Vulnerable checks of all types can be ignored with the following command:

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

  alias Sobelow.{Finding, Print, Utils}
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

    fingerprint_header = "Fingerprint: #{finding.fingerprint}"

    case Sobelow.format() do
      "json" ->
        json_finding = [
          type: finding.type,
          details: detail,
          file: finding.filename,
          cve: cve,
          line: 0,
          fingerprint: finding.fingerprint
        ]

        Sobelow.log_finding(json_finding, finding)

      "txt" ->
        Sobelow.log_finding(finding)

        Print.print_custom_finding_metadata(finding, [
          "Details: #{detail}",
          "File: #{finding.filename}",
          "CVE: #{cve}",
          fingerprint_header
        ])

      "compact" ->
        Print.log_compact_finding(finding)

      "flycheck" ->
        Print.log_flycheck_finding(finding)

      _ ->
        Sobelow.log_finding(finding)
    end
  end

  def details do
    @moduledoc
  end
end
