defmodule Sobelow.Misc.BinToTerm do
  @moduledoc """
  If user input is passed to Erlang's `binary_to_term` function
  it may result in memory exhaustion or code execution. Even with
  the `:safe` option, `binary_to_term` will deserialize functions,
  and shouldn't be considered safe to use with untrusted input.

  `binary_to_term` checks can be ignored with the following command:

      $ mix sobelow -i Misc.BinToTerm
  """
  alias Sobelow.Utils

  def run(fun, filename) do
    {vars, _params, {fun_name, [{_, line_no}]}} = parse_binary_term_def(fun)

    Enum.each vars, fn var ->
      print_finding(line_no, filename, fun_name, fun, var, :high)
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
    |> Enum.map(&Utils.extract_opts(&1, 0))
    |> List.flatten

    {erls, params, {fun_name, line_no}}
  end
end