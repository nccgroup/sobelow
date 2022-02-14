defmodule Sobelow.Formatter.SonarQube do
  @moduledoc false
  alias Sobelow.{Formatter, Finding}
  @behaviour Formatter

  @impl Formatter
  def format_findings(%{high: highs, medium: meds, low: lows}, vsn) do
    prefix = Application.get_env(:sobelow, :sonarqube_base_folder, "")
    issues = Enum.map(highs, fn {_type, finding} -> format_finding(finding, vsn, prefix) end)
             |> Enum.concat(Enum.map(meds, fn {_type, finding} -> format_finding(finding, vsn, prefix) end))
             |> Enum.concat(Enum.map(lows, fn {_type, finding} -> format_finding(finding, vsn, prefix) end))
    Jason.encode!(%{issues: issues}, pretty: true)
  end

  defp format_finding(%Finding{} = finding, vsn, prefix) do
    [modId, _] = String.split(finding.type, ":", parts: 2)
    rule = Sobelow.get_mod(modId)

    location = %{
      filePath: "#{prefix}#{finding.filename}",
      message: "#{finding.type} #{finding.vuln_variable} \n Help: #{rule.details()}"
    }

    location = with_text_range(location, finding)

    %{
      ruleId: rule.id(),
      severity: confidence_to_severity(finding.confidence),
      type: "VULNERABILITY",
      engineId: "sobelow-#{vsn}",
      primaryLocation: location
    }
  end

  defp with_text_range(%{} = location, %Finding{vuln_line_no: line}) when line > 0 do
    Map.put(location, :textRange, %{startLine: line})
  end

  defp with_text_range(%{} = location, %Finding{}), do: location

  defp confidence_to_severity(:high), do: "CRITICAL"
  defp confidence_to_severity(:medium), do: "MAJOR"
  defp confidence_to_severity(:low), do: "MINOR"
  defp confidence_to_severity(_), do: "INFO"

end
