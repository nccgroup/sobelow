defmodule Mix.Tasks.Sobelow do
  use Mix.Task
  @switches [with_code: :boolean, root: :string]

  def run(argv) do
    {opts, _, _} = OptionParser.parse(argv, @switches)

    Sobelow.run(opts)
  end
end