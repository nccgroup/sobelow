defmodule Sobelow.DOS.BinToAtom do
  @moduledoc """
  # Denial of Service via Unsafe Atom Interpolation

  In Elixir, atoms are not garbage collected. As such, if user input
  is used to create atoms (as in `:"foo\#{bar}"`, or in `:erlang.binary_to_atom`),
  it may result in memory exhaustion. Prefer the `String.to_existing_atom`
  function for untrusted user input.

  Atom interpolation checks can be ignored with the following command:

      $ mix sobelow -i DOS.BinToAtom
  """
  alias Sobelow.Utils
  use Sobelow.Finding

  @finding_type "Unsafe atom interpolation"

  def run(fun, meta_file) do
    severity = if meta_file.is_controller?, do: false, else: :low
    {findings, params, {fun_name, [{_, line_no}]}} = parse_def(fun)

    Enum.each findings, fn {finding, var} ->
      Utils.add_finding(line_no, meta_file.filename, fun, fun_name,
                        var, Utils.get_sev(params, var, severity),
                        finding, @finding_type)
    end
  end

  def parse_def(fun) do
    Utils.get_erlang_fun_vars_and_meta(fun, 0, :binary_to_atom, :erlang)
  end
end