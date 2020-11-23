defmodule Sobelow.SQL do
  @moduledoc """
  # SQL Injection

  SQL injection occurs when untrusted input is interpolated
  directly into a SQL query. In a typical Phoenix application,
  this would mean using the `Ecto.Adapters.SQL.query` method
  and not using the parameterization feature.

  Read more about SQL injection here:
  https://www.owasp.org/index.php/SQL_Injection

  SQL injection checks can be ignored with the following command:

      $ mix sobelow -i SQL
  """
  @submodules [Sobelow.SQL.Query, Sobelow.SQL.Stream]
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
