defmodule Sobelow.CI.System do
  use Sobelow.Finding
  @finding_type "Command Injection in `System.cmd`"

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
