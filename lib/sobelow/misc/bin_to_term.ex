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
  @finding_type "Unsafe `binary_to_term`"

  def run(fun, meta_file) do
    {vars, _params, {fun_name, [{_, line_no}]}} = parse_def(fun)

    Enum.each vars, fn {finding, var} ->
      Utils.add_finding(line_no, meta_file.filename, fun, fun_name,
                        var, :high, finding, @finding_type)
    end
  end

  def parse_def(fun) do
    Utils.get_erlang_fun_vars_and_meta(fun, 0, :binary_to_term, :erlang)
  end
end