defmodule Sobelow.FindingLog do
  use GenServer

  alias Poison, as: JSON

  @json_template """
  {
    "sobelow_version": "<%= @version %>",
    "total_findings": "<%= @total_findings %>",
    "findings": {<%= for {confidence, items} <- @findings do %>
      "<%= confidence %>": [<% last = List.last(items) %><%= for item <- items do %>
        {<% {lk, _} = List.last(item) %><%= for {k, v} <- item do %>
          "<%= k %>": "<%= v %>"<%= if lk != k do %>,<% end %><% end %>
        }<%= if last != item do %>,<% end %><% end %>
      ]<%= if confidence != :low_confidence do %>,<% end %><% end %>
    }
  }
  """

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

    JSON.encode!(
      %{
        sobelow_version: vsn,
        total_findings: length(highs) + length(meds) + length(lows),
        findings: %{
          high_confidence: highs,
          medium_confidence: meds,
          low_confidence: lows
        }
      },
      pretty: true
    )
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
end
