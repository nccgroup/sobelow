defmodule Sobelow.SQL.Query do
  @uid 17
  @finding_type "SQL.Query: SQL injection"

  use Sobelow.Finding

  def run(fun, meta_file) do
    confidence = if !meta_file.is_controller?, do: :low

    Finding.init(@finding_type, meta_file.filename, confidence)
    |> Finding.multi_from_def(fun, parse_sql_def(fun))
    |> Enum.each(&Print.add_finding(&1))

    Finding.init(@finding_type, meta_file.filename, confidence)
    |> Finding.multi_from_def(fun, parse_repo_query_def(fun))
    |> Enum.each(&Print.add_finding(&1))
  end

  ## query(repo, sql, params \\ [], opts \\ [])
  def parse_sql_def(fun) do
    Parse.get_fun_vars_and_meta(fun, 1, :query, :SQL)
  end

  def parse_repo_query_def(fun) do
    Parse.get_fun_vars_and_meta(fun, 0, :query, :Repo)
  end

  def details() do
    Sobelow.SQL.details()
  end
end
