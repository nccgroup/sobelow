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
  @uid 12
  @finding_type "DOS.ListToAtom: Unsafe `List.to_atom`"

  use Sobelow.Finding

  def run(fun, meta_file) do
    confidence = if !meta_file.is_controller?, do: :low

    Finding.init(@finding_type, meta_file.filename, confidence)
    |> Finding.multi_from_def(fun, parse_def(fun))
    |> Enum.each(&Print.add_finding(&1))
  end

  def parse_def(fun) do
    Parse.get_fun_vars_and_meta(fun, 0, :to_atom, [:List])
  end
end
