defmodule Sobelow.Misc do
  @moduledoc """
  # Miscellaneous

  This suite of tests is to be a catch-all for
  checks that don't fall neatly into the other
  detection categories.

  If you wish to learn more about the specific vulnerabilities
  found within the Miscellaneous category, you may run the
  following commands to find out more:

            $ mix sobelow -d Misc.BinToTerm

  Miscellaneous checks of all types can be ignored with the
  following command:

      $ mix sobelow -i Misc
  """
  @submodules [Sobelow.Misc.BinToTerm]
  use Sobelow.FindingType

  def get_vulns(fun, meta_file, _web_root, skip_mods \\ []) do
    allowed = @submodules -- (Sobelow.get_ignored() ++ skip_mods)

    Enum.each(allowed, fn mod ->
      apply(mod, :run, [fun, meta_file])
    end)
  end

  def details do
    @moduledoc
  end
end
