defmodule Sobelow.DOS.ListToAtom do
  @moduledoc """
  # Denial of Service via `List.to_atom`

  In Elixir, atoms are not garbage collected. As such, if user input
  is passed to the `List.to_atom` function, it may result in memory
  exhaustion. Prefer the `List.to_existing_atom` function for untrusted
  user input.

  `List.to_atom` checks can be ignored with the following command:

      $ mix sobelow -i DOS.ListToAtom
  """
  alias Sobelow.Utils
  use Sobelow.Finding
  @finding_type "Unsafe `List.to_atom`"

  def run(fun, filename) do
    severity = if String.ends_with?(filename, "_controller.ex"), do: false, else: :low
    {findings, params, {fun_name, [{_, line_no}]}} = parse_def(fun)

    Enum.each findings, fn {finding, var} ->
      Utils.add_finding(line_no, filename, fun, fun_name,
                        var, Utils.get_sev(params, var, severity),
                        finding, @finding_type)
    end
  end

  def parse_def(fun) do
    Utils.get_fun_vars_and_meta(fun, 0, :to_atom, [:List])
  end
end