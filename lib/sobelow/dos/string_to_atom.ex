defmodule Sobelow.DOS.StringToAtom do
  @moduledoc """
  # Denial of Service via `String.to_atom`

  In Elixir, atoms are not garbage collected. As such, if user input
  is passed to the `String.to_atom` function, it may result in memory
  exhaustion. Prefer the `String.to_existing_atom` function for untrusted
  user input.

  `String.to_atom` checks can be ignored with the following command:

      $ mix sobelow -i DOS.StringToAtom
  """
  alias Sobelow.Utils
  use Sobelow.Finding

  def run(fun, filename) do
    severity = if String.ends_with?(filename, "_controller.ex"), do: false, else: :low
    {vars, params, {fun_name, [{_, line_no}]}} = parse_def(fun)

    Enum.each vars, fn {find, var} ->
      add_finding(line_no, filename, fun_name,
                  fun, var, Utils.get_sev(params, var, severity))
    end
  end

  defp add_finding(line_no, filename, fun_name, fun, var, severity) do
    Utils.add_finding(line_no, filename, fun,
                      fun_name, var, severity,
                      "Unsafe `String.to_atom`", :to_atom, [:String])
  end

  def parse_def(fun) do
    Utils.get_fun_vars_and_meta(fun, 0, :to_atom, [:String])
  end
end