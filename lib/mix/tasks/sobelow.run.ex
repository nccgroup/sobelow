defmodule Mix.Tasks.Sobelow.Run do
  use Mix.Task

  def run(_) do
    Sobelow.run()
  end
end