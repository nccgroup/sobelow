defmodule Sobelow.DOS do
  @submodules [Sobelow.DOS.StringToAtom, Sobelow.DOS.ListToAtom, Sobelow.DOS.BinToAtom]
  use Sobelow.FindingType

  def get_vulns(fun, meta_file, _web_root, skip_mods \\ []) do
    allowed = @submodules -- (Sobelow.get_ignored() ++ skip_mods)

    Enum.each(allowed, fn mod ->
      apply(mod, :run, [fun, meta_file])
    end)
  end
end
