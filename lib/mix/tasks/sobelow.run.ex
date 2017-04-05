defmodule Mix.Tasks.Sobelow.Run do
  use Mix.Task
  alias Sobelow.Config

  def run(_) do
    Config.run()
  end
end