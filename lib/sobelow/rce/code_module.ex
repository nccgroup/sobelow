defmodule Sobelow.RCE.CodeModule do
  alias Sobelow.Utils
  use Sobelow.Finding
  @code_funs [:eval_string, :eval_file, :eval_quoted]

  def run(fun, meta_file) do
    severity = if meta_file.is_controller?, do: false, else: :low

    Enum.each @code_funs, fn code_fun ->
      {findings, params, {fun_name, [{_, line_no}]}} = parse_def(fun, code_fun)

      Enum.each findings, fn {finding, var} ->
        Utils.add_finding(line_no, meta_file.filename, fun, fun_name,
                          var, Utils.get_sev(params, var, severity),
                          finding, "Code Execution in `Code.#{code_fun}`")
      end
    end
  end

  def parse_def(fun, code_fun) do
    Utils.get_fun_vars_and_meta(fun, 0, code_fun, [:Code])
  end

  def details() do
    Sobelow.RCE.details()
  end
end