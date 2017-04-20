defmodule Sobelow.Traversal do
  alias Sobelow.Utils
  alias Sobelow.Traversal.{SendFile, FileModule}
  @submodules [Sobelow.Traversal.SendFile,
               Sobelow.Traversal.FileModule]

  def get_vulns(fun, filename, _web_root) do
    filename = String.replace_prefix(filename, "/", "")
    allowed = @submodules -- Sobelow.get_ignored()

    Enum.each allowed, fn mod ->
      apply(mod, :run, [fun, filename])
    end
  end
end