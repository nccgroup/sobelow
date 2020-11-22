defmodule Sobelow.RCE.EEx do
  @moduledoc """
  # Insecure EEx evaluation

  If user input is passed to EEx eval functions, it may result in
  arbitrary code execution. The root cause of these issues is often
  directory traversal.

  EEx checks can be ignored with the following command:

      $ mix sobelow -i RCE.EEx
  """
  @uid 16
  @finding_type "RCE.EEx: Code Execution in EEx template eval"

  use Sobelow.Finding
  @eex_funs [:eval_string, :eval_file]

  def run(fun, meta_file) do
    confidence = if !meta_file.is_controller?, do: :low

    Enum.each(@eex_funs, fn eex_fun ->
      "RCE.EEx: Code Execution in `EEx.#{eex_fun}`"
      |> Finding.init(meta_file.filename, confidence)
      |> Finding.multi_from_def(fun, parse_def(fun, eex_fun))
      |> Enum.each(&Print.add_finding(&1))
    end)
  end

  def parse_def(fun, eex_fun) do
    Parse.get_fun_vars_and_meta(fun, 0, eex_fun, [:EEx])
  end
end
