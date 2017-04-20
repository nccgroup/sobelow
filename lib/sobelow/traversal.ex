defmodule Sobelow.Traversal do
  alias Sobelow.Utils
  alias Sobelow.Traversal.{SendFile, FileModule}
  @submodules [Sobelow.Traversal.SendFile,
               Sobelow.Traversal.FileModule]

  def get_vulns(fun, filename, web_root) do
    filename = String.replace_prefix(filename, "/", "")
    path = web_root <> String.replace_prefix(filename, "web/", "")
    |> Path.expand("")
    |> String.replace_prefix("/", "")
    allowed = @submodules -- Sobelow.get_ignored()

    Enum.each allowed, fn mod ->
      apply(mod, :run, [fun, path])
    end
  end
end