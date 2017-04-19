defmodule Mix.Tasks.Sobelow do
  use Mix.Task
  @moduledoc """
  Sobelow is a static analysis tool for discovering
  vulnerabilities in Phoenix applications.

  This tool should be run in the root of the project directory
  with the following command:

      mix sobelow

  ## Command line options

  * `--root -r` - Specify application root directory
  * `--with-code -v` - Print vulnerable code snippets
  * `--ignore -i` - Ignore modules

  ## Supported modules

  * XSS
  * SQL
  * Config
  * Traversal
  * Misc

  These modules can be used for "ignore" functionality. For example:

      mix sobelow -i XSS,Traversal
  """
  @switches [with_code: :boolean, root: :string, ignore: :string]
  @aliases  [v: :with_code, r: :root, i: :ignore]

  def run(argv) do
    {opts, _, _} = OptionParser.parse(argv, aliases: @aliases, switches: @switches)

    with_code = Keyword.get(opts, :with_code, false)
    root = Keyword.get(opts, :root, ".")

    set_env(:with_code, with_code)
    set_env(:root, root)

    ignored =
      Keyword.get(opts, :ignore, "")
      |> String.split(",")

    set_env(:ignored, ignored)

    Sobelow.run()
  end

  def set_env(key, value) do
    Application.put_env(:sobelow, key, value)
  end
end