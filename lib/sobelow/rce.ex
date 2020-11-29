defmodule Sobelow.RCE do
  @moduledoc """
  # Remote Code Execution

  Remote Code Execution vulnerabilities are a result of
  untrusted user input being executed or interpreted by
  the system and may result in complete system compromise.

  Code Execution checks can be ignored with the
  following command:

      $ mix sobelow -i RCE
  """
  @submodules [Sobelow.RCE.EEx, Sobelow.RCE.CodeModule]
  use Sobelow.FindingType

  def get_vulns(fun, meta_file, _web_root, skip_mods \\ []) do
    allowed = @submodules -- (Sobelow.get_ignored() ++ skip_mods)

    Enum.each(allowed, fn mod ->
      apply(mod, :run, [fun, meta_file])
    end)
  end

  def details() do
    @moduledoc
  end
end
