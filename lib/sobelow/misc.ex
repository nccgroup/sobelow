defmodule Sobelow.Misc do
  @submodules [Sobelow.Misc.BinToTerm, Sobelow.Misc.FilePath]
  use Sobelow.FindingType

  def get_vulns(fun, filename, _web_root, skip_mods \\ []) do
    path = Path.expand(filename, "")
    |> String.replace_prefix("/", "")

    allowed = @submodules -- (Sobelow.get_ignored() ++ skip_mods)

    Enum.each allowed, fn mod ->
      apply(mod, :run, [fun, path])
    end
  end
end