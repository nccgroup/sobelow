defmodule Sobelow.Formatter.SonarQube do
  @moduledoc false
  alias Sobelow.{Formatter, Finding}
  @behaviour Formatter

  @impl Formatter
  def format_findings(%{high: highs, medium: meds, low: lows} = all, vsn) do
    prefix = Application.get_env(:sobelow, :sonarqube_base_folder, "")
    issues = Enum.map(highs, fn {_type, finding} -> format_finding(finding, vsn, prefix) end)
             |> Enum.concat(Enum.map(meds, fn {_type, finding} -> format_finding(finding, vsn, prefix) end))
             |> Enum.concat(Enum.map(lows, fn {_type, finding} -> format_finding(finding, vsn, prefix) end))
    Jason.encode!(%{issues: issues}, pretty: true)
  end

  defp format_finding(%Finding{} = finding, vsn, prefix) do
    [modId, _] = String.split(finding.type, ":", parts: 2)
    rule = Sobelow.get_mod(modId)
    %{
      ruleId: rule.id(),
      severity: confidence_to_severity(finding.confidence),
      type: "VULNERABILITY",
      engineId: "sobelow-#{vsn}",
      primaryLocation: %{
        filePath: "#{prefix}#{finding.filename}",
        message: "#{finding.type} #{finding.vuln_variable} \n Help: #{rule.details()}",
        textRange: %{
          startLine: finding.vuln_line_no
        }
      }
    }
  end

  defp confidence_to_severity(:high), do: "CRITICAL"
  defp confidence_to_severity(:medium), do: "MAJOR"
  defp confidence_to_severity(:low), do: "MINOR"
  defp confidence_to_severity(_), do: "INFO"

end
