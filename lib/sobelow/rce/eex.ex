defmodule Sobelow.RCE.EEx do
  @moduledoc """
  # Insecure EEx evaluation

  If user input is passed to EEx eval functions, it may result in
  arbitrary code execution. The root cause of these issues is often
  directory traversal.

  EEx checks can be ignored with the following command:

      $ mix sobelow -i RCE.EEx
  """
  alias Sobelow.Utils
  use Sobelow.Finding
  @eex_funs [:eval_string, :eval_file]

  def run(fun, meta_file) do
    severity = if meta_file.is_controller?, do: false, else: :low

    Enum.each @eex_funs, fn eex_fun ->
      {findings, params, {fun_name, [{_, line_no}]}} = parse_def(fun, eex_fun)

      Enum.each findings, fn {finding, var} ->
        Utils.add_finding(line_no, meta_file.filename, fun, fun_name,
                          var, Utils.get_sev(params, var, severity),
                          finding, "Code Execution in `EEx.#{eex_fun}`")
      end
    end
  end

  def parse_def(fun, eex_fun) do
    Utils.get_fun_vars_and_meta(fun, 0, eex_fun, [:EEx])
  end
end