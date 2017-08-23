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

  def run(fun, filename) do
    severity = if String.ends_with?(filename, "_controller.ex"), do: false, else: :low
    {vars, params, {fun_name, [{_, line_no}]}} = parse_def(fun)

    Enum.each vars, fn var ->
      add_finding(line_no, filename, fun_name,
                  fun, var, Utils.get_sev(params, var, severity))
    end
  end

  defp add_finding(line_no, filename, fun_name, fun, var, severity) do
    Utils.add_finding(line_no, filename, fun,
                      fun_name, var, severity,
                      "Unsafe atom interpolation", :binary_to_atom, :erlang)
  end

  def parse_def(fun) do
    Utils.get_erlang_fun_vars_and_meta(fun, 0, :binary_to_atom, :erlang)
  end
end