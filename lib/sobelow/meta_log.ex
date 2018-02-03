defmodule Sobelow.MetaLog do
  use GenServer

  def start_link() do
    GenServer.start_link(__MODULE__, :ok, name: __MODULE__)
  end

  def add_templates(templates) do
    GenServer.cast(__MODULE__, {:add, templates})
  end

  def get_templates() do
    GenServer.call(__MODULE__, :get_templates)
  end

  def init(:ok) do
    {:ok, %{:templates => %{}}}
  end

  def handle_cast({:add, templates}, log) do
    {:noreply, Map.put(log, :templates, templates)}
  end

  def handle_call(:get_templates, _from, log) do
    {:reply, log.templates, log}
  end
end
