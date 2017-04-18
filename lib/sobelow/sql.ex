defmodule Sobelow.SQL do
  alias Sobelow.SQL.Inject

  def get_vulns(fun, filename) do
    filename = String.replace_prefix(filename, "/", "")
    Inject.run(fun, filename)
  end
end