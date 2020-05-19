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
    highs = normalize(highs)
    meds = normalize(meds)
    lows = normalize(lows)

    format_json(%{
      findings: %{high_confidence: highs, medium_confidence: meds, low_confidence: lows},
      total_findings: length(highs) + length(meds) + length(lows),
      sobelow_version: vsn
    })
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

  def format_json(v, level \\ 0)

  def format_json(map, level) when is_map(map) do
    map
    |> Enum.map(fn {k, v} -> "\"#{k}\": #{format_json(v, level + 1)}" end)
    |> Enum.map(&indent(&1, level + 1))
    |> Enum.join(",\n")
    |> interpolate("{\n", "\n" <> indent("}", level))
  end

  def format_json(l, level) when is_list(l) do
    l
    |> Enum.map(&format_json(&1, level + 1))
    |> Enum.map(&indent(&1, level + 1))
    |> Enum.join(",\n")
    |> interpolate("[\n", "\n" <> indent("]", level))
  end

  def format_json(true, _), do: "true"
  def format_json(nil, _), do: "null"
  def format_json(false, _), do: "false"
  def format_json(atom, _) when is_atom(atom), do: "\"#{atom}\""
  def format_json(str, _) when is_binary(str), do: "\"#{str}\""

  def format_json({_, _, _} = var, _) do
    details = {var, [], []} |> Macro.to_string()
    "\"#{details}\""
  end

  def format_json(v, _), do: to_string(v)

  defp normalize(l), do: l |> Enum.map(&Map.new/1)

  defp indent(str, level), do: String.duplicate("   ", level) <> str

  defp interpolate(val, f, l), do: f <> val <> l
end
