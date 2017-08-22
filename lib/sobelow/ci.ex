defmodule Sobelow.CI do
  @moduledoc """
  # Command Injection

  Command Injection vulnerabilities are a result of
  passing untrusted input to an operating system shell,
  and may result in complete system compromise.

  Read more about Command Injection here:
  https://www.owasp.org/index.php/Command_Injection

  Command Injection checks can be ignored with the
  following command:

      $ mix sobelow -i CI
  """
  @submodules [Sobelow.CI.System, Sobelow.CI.OS]
  use Sobelow.FindingType

  def get_vulns(fun, filename, _web_root, skip_mods \\ []) do
    path = Path.expand(filename, "")
    |> String.replace_prefix("/", "")

    allowed = @submodules -- (Sobelow.get_ignored() ++ skip_mods)

    Enum.each allowed, fn mod ->
      apply(mod, :run, [fun, path])
    end
  end

  def details() do
    IO.ANSI.Docs.print(@moduledoc)
  end
end