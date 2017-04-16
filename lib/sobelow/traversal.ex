defmodule Sobelow.Traversal do
  alias Sobelow.Utilsx, as: Utils

  def get_vulns(fun, filename) do
    {vars, params, {fun_name, [{_, line_no}]}} = Utils.parse_send_file_def(fun)
    filename = String.replace_prefix(filename, "/", "")
    severity = if String.ends_with?(filename, "_controller.ex"), do: false, else: :low

    Enum.each vars, fn var ->
      if Enum.member?(params, var) || var === "conn.params" do
        print_finding(line_no, filename, fun_name, var, severity || :high)
      else
        print_finding(line_no, filename, fun_name, var, severity || :medium)
      end
    end

    {vars, params, {fun_name, [{_, line_no}]}} = Utils.parse_file_read_def(fun)

    Enum.each vars, fn var ->
      if Enum.member?(params, var) || var === "conn.params" do
        print_file_finding(line_no, filename, fun_name, var, :read, severity || :high)
      else
        print_file_finding(line_no, filename, fun_name, var, :read, severity || :medium)
      end
    end
  end

  defp print_file_finding(line_no, con, fun_name, var, :read, severity) do
    {color, confidence} = case severity do
      :high -> {IO.ANSI.red(), "High"}
      :medium -> {IO.ANSI.yellow(), "Medium"}
      :low -> {IO.ANSI.green(), "Low"}
    end
    IO.puts color <> "Directory Traversal in `File.read` - #{confidence} Confidence" <> IO.ANSI.reset()
    IO.puts "File: #{con} - #{fun_name}:#{line_no}"
    IO.puts "Variable: #{var}"
    IO.puts "\n-----------------------------------------------\n"
  end

  defp print_finding(line_no, con, fun_name, var, severity) do
    {color, confidence} = case severity do
      :high -> {IO.ANSI.red(), "High"}
      :medium -> {IO.ANSI.yellow(), "Medium"}
      :low -> {IO.ANSI.green(), "Low"}
    end
    IO.puts color <> "Directory Traversal in `send_file` - #{confidence} Confidence" <> IO.ANSI.reset()
    IO.puts "File: #{con} - #{fun_name}:#{line_no}"
    IO.puts "Variable: #{var}"
    IO.puts "\n-----------------------------------------------\n"
  end
end