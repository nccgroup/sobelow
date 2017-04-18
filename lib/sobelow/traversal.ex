defmodule Sobelow.Traversal do
  alias Sobelow.Utils
  alias Sobelow.Traversal.{SendFile, FileModule}

  def get_vulns(fun, filename) do
    filename = String.replace_prefix(filename, "/", "")
    SendFile.run(fun, filename)
    FileModule.run(fun, filename)
  end
end