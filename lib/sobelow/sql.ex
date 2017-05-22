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
  use Sobelow.Finding

  def get_vulns(fun, filename, web_root) do
    filename = String.replace_prefix(filename, "/", "")
    path = web_root <> String.replace_prefix(filename, "web/", "")
    |> Path.expand("")
    |> String.replace_prefix("/", "")
    allowed = @submodules -- Sobelow.get_ignored()

    Enum.each allowed, fn mod ->
      apply(mod, :run, [fun, path])
    end
  end
end