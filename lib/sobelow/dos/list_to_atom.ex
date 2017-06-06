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

  def run(fun, filename) do
    severity = if String.ends_with?(filename, "_controller.ex"), do: false, else: :low
    {vars, params, {fun_name, [{_, line_no}]}} = parse_def(fun)

    Enum.each vars, fn var ->
      if Enum.member?(params, var) || var === "conn.params" do
        Sobelow.log_finding("Unsafe `List.to_atom`", severity || :high)
        print_finding(line_no, filename, fun_name, fun, var, severity || :high)
      else
        Sobelow.log_finding("Unsafe `List.to_atom`", severity || :medium)
        print_finding(line_no, filename, fun_name, fun, var, severity || :medium)
      end
    end
  end

  defp print_finding(line_no, filename, fun_name, fun, var, severity) do
    Utils.print_finding_metadata(line_no, filename, fun,
                                   fun_name, var, severity,
                                   "Unsafe `List.to_atom`", :to_atom, [:List])
  end

  def parse_def(fun) do
    Utils.get_fun_vars_and_meta(fun, 0, :to_atom, [:List])
  end
end