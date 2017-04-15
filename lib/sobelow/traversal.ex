defmodule Sobelow.Traversal do
  alias Sobelow.Utils

  def get_vulns(fun, filename) do
    {vars, params, {fun_name, [{_, line_no}]}} = Utils.parse_send_file_def(fun)
    filename = String.replace_prefix(filename, "/", "")

    Enum.each vars, fn var ->
      if Enum.member?(params, var) || var === "conn.params" do
        print_finding(line_no, filename, fun_name, var, :high)
      else
        print_finding(line_no, filename, fun_name, var, :medium)
      end
    end

    {vars, params, {fun_name, [{_, line_no}]}} = Utils.parse_file_read_def(fun)

    Enum.each vars, fn var ->
      if Enum.member?(params, var) || var === "conn.params" do
        print_file_finding(line_no, filename, fun_name, var, :read, :high)
      else
        print_file_finding(line_no, filename, fun_name, var, :read, :medium)
      end
    end
  end

  defp print_file_finding(line_no, con, fun_name, var, :read, :high) do
    IO.puts IO.ANSI.red() <> "Directory Traversal in `File.read` - High Confidence" <> IO.ANSI.reset()
    IO.puts "File: #{con} - #{fun_name}:#{line_no}"
    IO.puts "Variable: #{var}"
    IO.puts "\n-----------------------------------------------\n"
  end

  defp print_file_finding(line_no, con, fun_name, var, :read, :medium) do
    IO.puts IO.ANSI.yellow() <> "Directory Traversal in `File.read` - Medium Confidence" <> IO.ANSI.reset()
    IO.puts "File: #{con} - #{fun_name}:#{line_no}"
    IO.puts "Variable: #{var}"
    IO.puts "\n-----------------------------------------------\n"
  end

  defp print_finding(line_no, con, fun_name, var, :high) do
    IO.puts IO.ANSI.red() <> "Directory Traversal in `send_file` - High Confidence" <> IO.ANSI.reset()
    IO.puts "File: #{con} - #{fun_name}:#{line_no}"
    IO.puts "Variable: #{var}"
    IO.puts "\n-----------------------------------------------\n"
  end

  defp print_finding(line_no, con, fun_name, var, :medium) do
    IO.puts IO.ANSI.yellow() <> "Directory Traversal in `send_file` - Medium Confidence" <> IO.ANSI.reset()
    IO.puts "File: #{con} - #{fun_name}:#{line_no}"
    IO.puts "Variable: #{var}"
    IO.puts "\n-----------------------------------------------\n"
  end
end