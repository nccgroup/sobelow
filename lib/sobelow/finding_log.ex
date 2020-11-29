defmodule Sobelow.FindingLog do
  use GenServer

  def start_link() do
    GenServer.start_link(__MODULE__, :ok, name: __MODULE__)
  end

  def add(finding, severity) do
    GenServer.cast(__MODULE__, {:add, finding, severity})
  end

  def log() do
    GenServer.call(__MODULE__, :log)
  end

  def json(vsn) do
    %{high: highs, medium: meds, low: lows} = log()
    highs = normalize_json_log(highs)
    meds = normalize_json_log(meds)
    lows = normalize_json_log(lows)

    Jason.encode!(
      format_json(%{
        findings: %{high_confidence: highs, medium_confidence: meds, low_confidence: lows},
        total_findings: length(highs) + length(meds) + length(lows),
        sobelow_version: vsn
      }),
      pretty: true
    )
  end

  def sarif(vsn) do
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
            results: sarif_results()
          }
        ]
      },
      pretty: true
    )
  end

  def sarif_results() do
    %{high: highs, medium: meds, low: lows} = log()

    highs = normalize_sarif_log(highs)
    meds = normalize_sarif_log(meds)
    lows = normalize_sarif_log(lows)

    Enum.map(highs, &format_sarif/1) ++
      Enum.map(meds, &format_sarif/1) ++ Enum.map(lows, &format_sarif/1)
  end

  def quiet() do
    total = total(log())
    findings = if total > 1, do: "findings", else: "finding"

    if total > 0 do
      "Sobelow: #{total} #{findings} found. Run again without --quiet to review findings."
    end
  end

  defp total(%{high: highs, medium: meds, low: lows}) do
    length(highs) + length(meds) + length(lows)
  end

  def init(:ok) do
    {:ok, %{:high => [], :medium => [], :low => []}}
  end

  def handle_cast({:add, finding, severity}, findings) do
    {:noreply, Map.update!(findings, severity, &[finding | &1])}
  end

  def handle_call(:log, _from, findings) do
    {:reply, findings, findings}
  end

  def format_json(map) when is_map(map) do
    map |> Enum.map(fn {k, v} -> {k, format_json(v)} end) |> Enum.into(%{})
  end

  def format_json(l) when is_list(l) do
    l |> Enum.map(&format_json(&1))
  end

  def format_json({_, _, _} = var) do
    details = {var, [], []} |> Macro.to_string()
    "\"#{details}\""
  end

  def format_json(n), do: n

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

  defp normalize_json_log(finding), do: finding |> Stream.map(fn {d, _} -> d end) |> normalize()

  defp normalize_sarif_log(finding),
    do: finding |> Stream.map(fn {_, f} -> Map.from_struct(f) end) |> normalize()

  defp normalize(l), do: l |> Enum.map(&Map.new/1)
end
