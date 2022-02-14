defmodule Sobelow.Formatter.Json do
  @moduledoc false
  alias Sobelow.Formatter
  @behaviour Formatter

  @impl Formatter
  def format_findings(%{high: highs, medium: meds, low: lows}, vsn) do
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

  defp format_json(map) when is_map(map) do
    map |> Enum.map(fn {k, v} -> {k, format_json(v)} end) |> Enum.into(%{})
  end

  defp format_json(l) when is_list(l) do
    l |> Enum.map(&format_json(&1))
  end

  defp format_json({_, _, _} = var) do
    details = {var, [], []} |> Macro.to_string()
    "\"#{details}\""
  end

  defp format_json(n), do: n

  defp normalize_json_log(finding), do: finding |> Stream.map(fn {d, _} -> d end) |> normalize()

  defp normalize(l), do: l |> Enum.map(&Map.new/1)

end
