defmodule Sobelow.DOS do
  @moduledoc """
  # Denial of Service

  The Denial of Service (DOS) attack is focused on making a
  resource (site, application, server) unavailable for the
  purpose it was designed.

  Read more about Denial of Service here:
  https://owasp.org/www-community/attacks/Denial_of_Service

  If you wish to learn more about the specific vulnerabilities
  found within the Denial of Service category, you may run the
  following commands to find out more:

          $ mix sobelow -d DOS.StringToAtom
          $ mix sobelow -d DOS.ListToAtom
          $ mix sobelow -d DOS.BinToAtom

  Denial of Service checks of all types can be ignored with the
  following command:

      $ mix sobelow -i DOS
  """
  @submodules [Sobelow.DOS.StringToAtom, Sobelow.DOS.ListToAtom, Sobelow.DOS.BinToAtom]
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
