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

  def json() do
    %{high: high, medium: med, low: low} = log()

    """
    {

    }
    """
  end

  def init(:ok) do
    {:ok, %{:high => [], :medium => [], :low => []}}
  end

  def handle_cast({:add, finding, severity}, findings) do
    {:noreply, Map.update!(findings, severity, &([finding|&1]))}
  end

  def handle_call(:log, _from, findings) do
    {:reply, findings, findings}
  end

end