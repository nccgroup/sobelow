defmodule Mix.Tasks.Sobelow do
  use Mix.Task
  @moduledoc """
  Sobelow is a static analysis tool for discovering
  vulnerabilities in Phoenix applications.

  This tool should be run in the root of the project directory
  with the following command:

      mix sobelow

  Or by using the "--root" flag:

      mix sobelow --root apps/umbrella_web

  To see vulnerable code snippets, use the "--with-code" flag:

      mix sobelow --with-code
  """
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