defmodule Sobelow.Misc.BinToTerm do
  @moduledoc """
  # Insecure use of `binary_to_term`

  If user input is passed to Erlang's `binary_to_term` function
  it may result in memory exhaustion or code execution. Even with
  the `:safe` option, `binary_to_term` will deserialize functions,
  and shouldn't be considered safe to use with untrusted input.

  `binary_to_term` checks can be ignored with the following command:

      $ mix sobelow -i Misc.BinToTerm
  """
  alias Sobelow.Utils
  use Sobelow.Finding

  def run(fun, filename) do
    {vars, _params, {fun_name, [{_, line_no}]}} = parse_binary_term_def(fun)

    Enum.each vars, fn var ->
      Sobelow.log_finding("Unsafe `binary_to_term`", :high)
      print_finding(line_no, filename, fun_name, fun, var, :high)
    end
  end

  defp print_finding(line_no, filename, fun_name, fun, var, severity) do
    Utils.print_finding_metadata(line_no, filename, fun,
                                   fun_name, var, severity,
                                   "Unsafe `binary_to_term`", :binary_to_term, :erlang)
  end

  def parse_binary_term_def(fun) do
    {params, {fun_name, line_no}} = Utils.get_fun_declaration(fun)

    pipefuns = Utils.get_pipe_funs(fun)
    |> Enum.map(fn {_, _, opts} -> Enum.at(opts, 1) end)
    |> Enum.flat_map(&Utils.get_erlang_funs_of_type(&1, :binary_to_term))

    pipeerls = Enum.flat_map(pipefuns, &Utils.get_pipe_val(fun, &1))
    |> List.flatten

    erls = Utils.get_erlang_funs_of_type(fun, :binary_to_term) -- pipefuns
    |> Enum.map(&Utils.extract_opts(&1, 0))
    |> List.flatten

    {erls ++ pipeerls, params, {fun_name, line_no}}
  end
end