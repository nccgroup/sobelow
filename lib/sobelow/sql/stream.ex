defmodule Sobelow.SQL.Stream do
  alias Sobelow.Utils
  use Sobelow.Finding

  def run(fun, filename) do
    {interp_vars, params, {fun_name, [{_, line_no}]}} = parse_sql_def(fun)
    severity = if String.ends_with?(filename, "_controller.ex"), do: false, else: :low

    Enum.each(interp_vars, fn var ->
      if Enum.member?(params, var) do
        Sobelow.log_finding("SQLi", severity || :high)
        print_finding(line_no, filename, fun, fun_name, var, severity || :high)
      else
        Sobelow.log_finding("SQLi", severity || :medium)
        print_finding(line_no, filename, fun, fun_name, var, severity || :medium)
      end
    end)
  end

  ## stream(repo, sql, params \\ [], opts \\ [])
  def parse_sql_def(fun) do
    Utils.get_fun_vars_and_meta(fun, 1, :stream, :SQL)
  end

  defp print_finding(line_no, filename, fun, fun_name, var, severity) do
    Utils.print_finding_metadata(line_no, filename, fun, fun_name, var, severity, "SQL injection", :stream, :SQL)
  end

  def get_details() do
    Sobelow.SQL.details()
  end
end