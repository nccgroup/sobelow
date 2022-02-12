defmodule Sobelow.Formatter.SonarQube do
  @moduledoc false
  alias Sobelow.{Formatter, Finding}
  @behaviour Formatter

  @impl Formatter
  def format_findings(%{high: highs, medium: meds, low: lows}, vsn) do
    issues = Enum.map(highs, fn {_type, finding} -> format_finding(finding, vsn) end)
             |> Enum.concat(Enum.map(meds, fn {_type, finding} -> format_finding(finding, vsn) end))
             |> Enum.concat(Enum.map(lows, fn {_type, finding} -> format_finding(finding, vsn) end))
    Jason.encode!(%{issues: issues}, pretty: true)
  end

  defp format_finding(%Finding{} = finding, vsn) do
    %{
      engineId: "sobelow-#{vsn}",
      primaryLocation: %{
        filePath: "./#{finding.filename}",
        message: "#{finding.type} #{finding.vuln_variable}",
        textRange: %{
          startLine: finding.vuln_line_no
        }
      },
      ruleId: finding.type,
      severity: confidence_to_severity(finding.confidence),
      type: "VULNERABILITY"
    }
  end

  defp confidence_to_severity(:high), do: "CRITICAL"
  defp confidence_to_severity(:medium), do: "MAJOR"
  defp confidence_to_severity(:low), do: "MINOR"
  defp confidence_to_severity(_), do: "INFO"

end
