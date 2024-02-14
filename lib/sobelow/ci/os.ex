defmodule Sobelow.CI.OS do
  @moduledoc """
  # Command Injection in `:os.cmd`

  This submodule of the `CI` module checks for Command Injection
  vulnerabilities through usage of the `:os.cmd` function.

  Ensure the the command passed to `:os.cmd` is not user-controlled.

  `:os.cmd` Injection checks can be ignored with the following command:

      $ mix sobelow -i CI.OS
  """
  @uid 1
  @finding_type "CI.OS: Command Injection in `:os.cmd`"

  use Sobelow.Finding

  def run(fun, meta_file) do
    confidence = if !meta_file.controller?, do: :low

    Finding.init(@finding_type, meta_file.filename, confidence)
    |> Finding.multi_from_def(fun, parse_def(fun))
    |> Enum.each(&Print.add_finding(&1))
  end

  def parse_def(fun) do
    Parse.get_erlang_fun_vars_and_meta(fun, 0, :cmd, :os)
  end
end
