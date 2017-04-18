defmodule Sobelow.Misc do
  alias Sobelow.Misc.BinToTerm

  def get_vulns(fun, filename) do
    filename = String.replace_prefix(filename, "/", "")
    BinToTerm.run(fun, filename)
  end
end