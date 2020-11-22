defmodule Sobelow.CI.OS do
  @uid 1
  @finding_type "CI.OS: Command Injection in `:os.cmd`"

  use Sobelow.Finding

  def run(fun, meta_file) do
    confidence = if !meta_file.is_controller?, do: :low

    Finding.init(@finding_type, meta_file.filename, confidence)
    |> Finding.multi_from_def(fun, parse_def(fun))
    |> Enum.each(&Print.add_finding(&1))
  end

  def parse_def(fun) do
    Parse.get_erlang_fun_vars_and_meta(fun, 0, :cmd, :os)
  end

  def details() do
    Sobelow.CI.details()
  end
end
