defmodule Sobelow.SQL.Stream do
  alias Sobelow.{Parse, Print}
  use Sobelow.Finding
  @finding_type "SQL.Stream: SQL injection"

  def run(fun, meta_file) do
    {findings, params, {fun_name, line_no}} = parse_sql_def(fun)
    severity = if meta_file.is_controller?, do: false, else: :low

    Enum.each(findings, fn {finding, var} ->
      Print.add_finding(
        line_no,
        meta_file.filename,
        fun,
        fun_name,
        var,
        Print.get_sev(params, var, severity),
        finding,
        @finding_type
      )
    end)
  end

  ## stream(repo, sql, params \\ [], opts \\ [])
  def parse_sql_def(fun) do
    Parse.get_fun_vars_and_meta(fun, 1, :stream, :SQL)
  end

  def details() do
    Sobelow.SQL.details()
  end
end
