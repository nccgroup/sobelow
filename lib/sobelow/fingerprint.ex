defmodule Sobelow.Fingerprint do
  @moduledoc false

  if Version.match?(System.build_info().version, ">= 1.5.0") do
    use Agent
  end

  def start_link() do
    Agent.start_link(fn -> {MapSet.new(), MapSet.new()} end, name: __MODULE__)
  end

  def value do
    Agent.get(__MODULE__, & &1)
  end

  def new_skips do
    Agent.get(__MODULE__, fn {total_set, ignore_set} ->
      MapSet.difference(total_set, ignore_set) |> MapSet.to_list()
    end)
  end

  def put(fingerprint) do
    Agent.update(__MODULE__, fn {total_set, ignore_set} ->
      {MapSet.put(total_set, fingerprint), ignore_set}
    end)
  end

  def put_ignore(fingerprint) do
    Agent.update(__MODULE__, fn {total_set, ignore_set} ->
      {total_set, MapSet.put(ignore_set, fingerprint)}
    end)
  end

  def member?(fingerprint) do
    Agent.get(__MODULE__, fn {_, ignore_set} -> MapSet.member?(ignore_set, fingerprint) end)
  end
end
