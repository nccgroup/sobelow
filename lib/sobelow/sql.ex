defmodule Sobelow.SQL do
  alias Sobelow.Utils

  def get_vulns(fun, filename) do
    {interp_vars, params, {fun_name, [{_, line_no}]}} = Utils.parse_sql_def(fun)
    filename = String.replace_prefix(filename, "/", "")

    Enum.each(interp_vars, fn var ->
      if Enum.member?(params, var) do
        print_finding(line_no, filename, fun_name, var, :high)
      else
        print_finding(line_no, filename, fun_name, var, :medium)
      end
    end)
  end

  defp print_finding(line_no, con, fun_name, var, :high) do
    IO.puts IO.ANSI.red() <> "SQL injection - High Confidence" <> IO.ANSI.reset()
    IO.puts "File: #{con} - #{fun_name}:#{line_no}"
    IO.puts "Variable: #{var}"
    IO.puts "\n-----------------------------------------------\n"
  end

  defp print_finding(line_no, con, fun_name, var, :medium) do
    IO.puts IO.ANSI.yellow() <> "SQL injection - Medium Confidence" <> IO.ANSI.reset()
    IO.puts "File: #{con} - #{fun_name}:#{line_no}"
    IO.puts "Variable: #{var}"
    IO.puts "\n-----------------------------------------------\n"
  end
end