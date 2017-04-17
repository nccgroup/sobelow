defmodule Sobelow.Misc do
  alias Sobelow.Utils

  def get_vulns(fun, filename) do
    {vars, _params, {fun_name, [{_, line_no}]}} = Utils.parse_binary_term_def(fun)
    filename = String.replace_prefix(filename, "/", "")

    Enum.each vars, fn var ->
      print_finding(line_no, filename, fun_name, fun, var, :low)
    end
  end

  defp print_finding(line_no, filename, fun_name, fun, var, severity) do
    {color, confidence} = case severity do
      :high -> {IO.ANSI.red(), "High"}
      :medium -> {IO.ANSI.yellow(), "Medium"}
      :low -> {IO.ANSI.green(), "Low"}
    end
    IO.puts color <> "Unsafe `binary_to_term` - #{confidence} Confidence" <> IO.ANSI.reset()
    IO.puts "File: #{filename} - #{fun_name}:#{line_no}"
    IO.puts "Variable: #{var}"
    if Sobelow.get_env(:with_code), do: Utils.print_code(fun, var, :binary_to_term)
    IO.puts "\n-----------------------------------------------\n"
  end
end