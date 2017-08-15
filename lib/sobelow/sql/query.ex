defmodule Sobelow.SQL.Query do
  alias Sobelow.Utils
  use Sobelow.Finding

  def run(fun, filename) do
    {interp_vars, params, {fun_name, [{_, line_no}]}} = parse_sql_def(fun)
    severity = if String.ends_with?(filename, "_controller.ex"), do: false, else: :low

    Enum.each(interp_vars, fn var ->
      print_finding(line_no, filename, fun_name,
                    fun, var, Utils.get_sev(params, var, severity))
    end)

    {interp_vars, params, {fun_name, [{_, line_no}]}} = parse_repo_query_def(fun)

    Enum.each(interp_vars, fn var ->
      print_repo_finding(line_no, filename, fun_name,
                         fun, var, Utils.get_sev(params, var, severity))
    end)
  end

  ## query(repo, sql, params \\ [], opts \\ [])
  def parse_sql_def(fun) do
    Utils.get_fun_vars_and_meta(fun, 1, :query, :SQL)
  end

  def parse_repo_query_def(fun) do
    Utils.get_fun_vars_and_meta(fun, 0, :query, :Repo)
  end

  defp print_finding(line_no, filename, fun_name, fun, var, severity) do
    Utils.add_finding(line_no, filename, fun,
                      fun_name, var, severity,
                      "SQL injection", :query, :SQL)
  end
  defp print_repo_finding(line_no, filename, fun_name, fun, var, severity) do
    Utils.add_finding(line_no, filename, fun,
                      fun_name, var, severity,
                      "SQL injection", :query, :Repo)
  end

  def get_details() do
    Sobelow.SQL.details()
  end
end
