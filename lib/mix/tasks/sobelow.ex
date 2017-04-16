defmodule Mix.Tasks.Sobelow do
  use Mix.Task
  @switches [with_code: :boolean, root: :string]

  def run(argv) do
    {opts, _, _} = OptionParser.parse(argv, @switches)

    with_code = Keyword.get(opts, :with_code, false)
    root = Keyword.get(opts, :root, ".")

    set_env(:with_code, with_code)
    set_env(:root, root)

    Sobelow.run()
  end

  def set_env(key, value) do
    Application.put_env(:sobelow, key, value)
  end
end