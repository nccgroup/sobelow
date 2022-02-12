defmodule Sobelow.Formatter.Quiet do
  @moduledoc false
  alias Sobelow.Formatter
  @behaviour Formatter

  @impl Formatter
  def format_findings(%{high: _highs, medium: _meds, low: _lows} = log, _vsn) do
    total = total(log)
    findings = if total > 1, do: "findings", else: "finding"

    if total > 0 do
      "Sobelow: #{total} #{findings} found. Run again without --quiet to review findings."
    end
  end

  defp total(%{high: highs, medium: meds, low: lows}) do
    length(highs) + length(meds) + length(lows)
  end

end
