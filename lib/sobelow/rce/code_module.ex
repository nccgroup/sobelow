defmodule Sobelow.RCE.CodeModule do
  @uid 15
  @finding_type "RCE.CodeModule: Code execution in eval function"

  use Sobelow.Finding
  @code_funs [:eval_string, :eval_file, :eval_quoted]

  def run(fun, meta_file) do
    confidence = if !meta_file.is_controller?, do: :low

    Enum.each(@code_funs, fn code_fun ->
      "RCE.CodeModule: Code Execution in `Code.#{code_fun}`"
      |> Finding.init(meta_file.filename, confidence)
      |> Finding.multi_from_def(fun, parse_def(fun, code_fun))
      |> Enum.each(&Print.add_finding(&1))
    end)
  end

  def parse_def(fun, code_fun) do
    Parse.get_fun_vars_and_meta(fun, 0, code_fun, [:Code])
  end

  def details() do
    Sobelow.RCE.details()
  end
end
