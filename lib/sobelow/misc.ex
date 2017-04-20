defmodule Sobelow.Misc do
  alias Sobelow.Misc.BinToTerm
  @submodules [Sobelow.Misc.BinToTerm]

  def get_vulns(fun, filename, _web_root) do
    filename = String.replace_prefix(filename, "/", "")
    allowed = @submodules -- Sobelow.get_ignored()

    Enum.each allowed, fn mod ->
      apply(mod, :run, [fun, filename])
    end
  end
end