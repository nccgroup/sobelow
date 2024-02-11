defmodule Sobelow.SQL.Query do
  @moduledoc """
  # SQL Injection in Query

  This submodule of the `SQL` module checks for SQL injection
  vulnerabilities through usage of the `Ecto.Adapters.SQL.query`
  and `Ecto.Adapters.SQL.query!`.

  Ensure that the query is parameterized and not user-controlled.

  SQLi Query checks can be ignored with the following command:

      $ mix sobelow -i SQL.Query
  """
  @uid 17
  @finding_type "SQL.Query: SQL injection"
  @query_funcs [:query, :query!]

  use Sobelow.Finding

  def run(fun, meta_file) do
    confidence = if !meta_file.is_controller?, do: :low

    Enum.each(@query_funcs, fn query_func ->
      Finding.init(@finding_type, meta_file.filename, confidence)
      |> Finding.multi_from_def(fun, parse_sql_def(fun, query_func))
      |> Enum.each(&Print.add_finding(&1))
    end)

    Enum.each(@query_funcs, fn query_func ->
      Finding.init(@finding_type, meta_file.filename, confidence)
      |> Finding.multi_from_def(fun, parse_repo_query_def(fun, query_func))
      |> Enum.each(&Print.add_finding(&1))
    end)
  end

  ## query(repo, sql, params \\ [], opts \\ [])
  def parse_sql_def(fun, type) do
    Parse.get_fun_vars_and_meta(fun, 1, type, :SQL)
  end

  def parse_repo_query_def(fun, type) do
    Parse.get_fun_vars_and_meta(fun, 0, type, :Repo)
  end
end
