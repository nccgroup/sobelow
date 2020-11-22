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
  @uid 13
  @finding_type "DOS.StringToAtom: Unsafe `String.to_atom`"

  use Sobelow.Finding

  def run(fun, meta_file) do
    confidence = if !meta_file.is_controller?, do: :low

    Finding.init(@finding_type, meta_file.filename, confidence)
    |> Finding.multi_from_def(fun, parse_def(fun))
    |> Enum.each(&Print.add_finding(&1))
  end

  def parse_def(fun) do
    Parse.get_fun_vars_and_meta(fun, 0, :to_atom, [:String])
  end
end
