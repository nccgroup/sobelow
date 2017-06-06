defmodule Sobelow.DOS do
  @submodules [Sobelow.DOS.StringToAtom, Sobelow.DOS.ListToAtom]
  use Sobelow.Finding

  def get_vulns(fun, filename, web_root, skip_mods \\ []) do
    filename = String.replace_prefix(filename, "/", "")
    path = web_root <> String.replace_prefix(filename, "web/", "")
    |> Path.expand("")
    |> String.replace_prefix("/", "")
    allowed = @submodules -- (Sobelow.get_ignored() ++ skip_mods)

    Enum.each allowed, fn mod ->
      apply(mod, :run, [fun, path])
    end
  end
end