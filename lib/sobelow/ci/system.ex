defmodule Sobelow.CI.System do
  @moduledoc """
  # Command Injection via `System`

  This submodule of the `CI` module checks for Command Injection
  vulnerabilities through usage of the `System.cmd` function.

  Ensure the the command passed to `System.cmd` is not user-controlled.

  `System.cmd` Injection checks can be ignored with the following command:

      $ mix sobelow -i CI.System
  """
  @uid 2
  @finding_type "CI.System: Command Injection via `System` function"

  use Sobelow.Finding

  def run(fun, meta_file) do
    confidence = if !meta_file.controller?, do: :low

    Finding.init(@finding_type, meta_file.filename, confidence)
    |> Finding.multi_from_def(fun, parse_def(fun))
    |> Enum.each(&Print.add_finding(&1))

    Finding.init(@finding_type, meta_file.filename, confidence)
    |> Finding.multi_from_def(fun, parse_def_shell(fun))
    |> Enum.each(&Print.add_finding(&1))
  end

  def parse_def(fun) do
    Parse.get_fun_vars_and_meta(fun, 0, :cmd, [:System])
  end

  def parse_def_shell(fun) do
    Parse.get_fun_vars_and_meta(fun, 0, :shell, [:System])
  end
end
