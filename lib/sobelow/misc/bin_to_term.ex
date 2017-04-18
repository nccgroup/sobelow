defmodule Sobelow.Misc.BinToTerm do
  alias Sobelow.Utils

  def run(fun, filename) do
    {vars, _params, {fun_name, [{_, line_no}]}} = parse_binary_term_def(fun)

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

  def parse_binary_term_def(fun) do
    {params, {fun_name, line_no}} = Utils.get_fun_declaration(fun)

    erls = Utils.get_erlang_funs_of_type(fun, :binary_to_term)
    |> Enum.map(&Utils.extract_opts/1)
    |> List.flatten

    {erls, params, {fun_name, line_no}}
  end
end