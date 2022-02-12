defmodule Sobelow.FindingLog do
  use GenServer
  alias Sobelow.Formatter.{SonarQube, Json, Sarif, Quiet}

  def start_link() do
    GenServer.start_link(__MODULE__, :ok, name: __MODULE__)
  end

  def add(finding, severity) do
    GenServer.cast(__MODULE__, {:add, finding, severity})
  end

  def log() do
    GenServer.call(__MODULE__, :log)
  end

  def formatted_output("sonarqube", vsn), do: SonarQube.format_findings(log(), vsn)
  def formatted_output("json", vsn), do: Json.format_findings(log(), vsn)
  def formatted_output("sarif", vsn), do: Sarif.format_findings(log(), vsn)
  def formatted_output("quiet", vsn), do: Quiet.format_findings(log(), vsn)
  def formatted_output(_, _vsn), do: nil

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
