defmodule Sobelow.Formatter.Sarif do
  @moduledoc false
  alias Sobelow.Formatter
  @behaviour Formatter

  @impl Formatter
  def format_findings(%{high: _highs, medium: _meds, low: _lows} = log, vsn) do
    Jason.encode!(
      %{
        version: "2.1.0",
        "$schema":
          "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        runs: [
          %{
            tool: %{
              driver: %{
                name: "Sobelow",
                informationUri: "https://sobelow.io",
                semanticVersion: vsn,
                rules: Sobelow.rules()
              }
            },
            results: sarif_results(log)
          }
        ]
      },
      pretty: true
    )
  end

  defp sarif_results(%{high: highs, medium: meds, low: lows}) do
    highs = normalize_sarif_log(highs)
    meds = normalize_sarif_log(meds)
    lows = normalize_sarif_log(lows)

    Enum.map(highs, &format_sarif/1) ++
    Enum.map(meds, &format_sarif/1) ++ Enum.map(lows, &format_sarif/1)
  end

  defp format_sarif(finding) do
    [mod, _] = String.split(finding.type, ":", parts: 2)

    %{
      ruleId: Sobelow.get_mod(mod).id,
      message: %{
        text: finding.type
      },
      locations: [
        %{
          physicalLocation: %{
            artifactLocation: %{
              uri: finding.filename
            },
            region: %{
              startLine: sarif_num(finding.vuln_line_no),
              startColumn: sarif_num(finding.vuln_col_no),
              endLine: sarif_num(finding.vuln_line_no),
              endColumn: sarif_num(finding.vuln_col_no)
            }
          }
        }
      ],
      partialFingerprints: %{
        primaryLocationLineHash: finding.fingerprint
      },
      level: to_level(finding.confidence)
    }
  end

  defp to_level(:high), do: "error"
  defp to_level(_), do: "warning"

  defp sarif_num(0), do: 1
  defp sarif_num(num), do: num

  defp normalize_sarif_log(finding),
       do: finding
           |> Stream.map(fn {_, f} -> Map.from_struct(f) end)
           |> normalize()

  defp normalize(l),
       do: l
           |> Enum.map(&Map.new/1)

end
