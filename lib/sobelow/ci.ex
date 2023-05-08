defmodule Sobelow.CI do
  @moduledoc """
  # Command Injection

  Command Injection vulnerabilities are a result of
  passing untrusted input to an operating system shell,
  and may result in complete system compromise.

  Read more about Command Injection here:
  https://www.owasp.org/index.php/Command_Injection

  If you wish to learn more about the specific vulnerabilities
  found within the Command Injection category, you may run the
  following commands to find out more:

        $ mix sobelow -d CI.OS
        $ mix sobelow -d CI.System

  Command Injection checks of all types can be ignored with the
  following command:

      $ mix sobelow -i CI
  """
  @submodules [Sobelow.CI.System, Sobelow.CI.OS]
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
