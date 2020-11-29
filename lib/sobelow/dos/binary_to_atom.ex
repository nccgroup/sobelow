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
  @uid 11
  @finding_type "DOS.BinToAtom: Unsafe atom interpolation"

  use Sobelow.Finding

  def run(fun, meta_file) do
    confidence = if !meta_file.is_controller?, do: :low

    Finding.init(@finding_type, meta_file.filename, confidence)
    |> Finding.multi_from_def(fun, parse_def(fun))
    |> Enum.each(&Print.add_finding(&1))
  end

  def parse_def(fun) do
    Parse.get_erlang_fun_vars_and_meta(fun, 0, :binary_to_atom, :erlang)
  end
end
