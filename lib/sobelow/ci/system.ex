defmodule Sobelow.CI.System do
  @uid 2
  @finding_type "CI.System: Command Injection in `System.cmd`"

  use Sobelow.Finding

  def run(fun, meta_file) do
    confidence = if !meta_file.is_controller?, do: :low

    Finding.init(@finding_type, meta_file.filename, confidence)
    |> Finding.multi_from_def(fun, parse_def(fun))
    |> Enum.each(&Print.add_finding(&1))
  end

  def parse_def(fun) do
    Parse.get_fun_vars_and_meta(fun, 0, :cmd, [:System])
  end

  def details() do
    Sobelow.CI.details()
  end
end
