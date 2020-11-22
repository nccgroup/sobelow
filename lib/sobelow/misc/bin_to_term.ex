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
  @uid 14
  @finding_type "Misc.BinToTerm: Unsafe `binary_to_term`"

  use Sobelow.Finding

  def run(fun, meta_file) do
    Finding.init(@finding_type, meta_file.filename, :high)
    |> Finding.multi_from_def(fun, parse_def(fun))
    |> Enum.each(&Print.add_finding(&1))
  end

  def parse_def(fun) do
    Parse.get_erlang_fun_vars_and_meta(fun, 0, :binary_to_term, :erlang)
  end
end
