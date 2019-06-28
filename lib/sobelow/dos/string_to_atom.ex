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
  alias Sobelow.{Parse, Print}
  use Sobelow.Finding
  @finding_type "DOS.StringToAtom: Unsafe `String.to_atom`"

  def run(fun, meta_file) do
    severity = if meta_file.is_controller?, do: false, else: :low
    {findings, params, {fun_name, line_no}} = parse_def(fun)

    Enum.each(findings, fn {finding, var} ->
      Print.add_finding(
        line_no,
        meta_file.filename,
        fun,
        fun_name,
        var,
        Print.get_sev(params, var, severity),
        finding,
        @finding_type
      )
    end)
  end

  def parse_def(fun) do
    Parse.get_fun_vars_and_meta(fun, 0, :to_atom, [:String])
  end
end
