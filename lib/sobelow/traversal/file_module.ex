defmodule Sobelow.Traversal.FileModule do
  alias Sobelow.Utils
  use Sobelow.Finding
  @file_funcs [:read,
               :read!,
               :write,
               :write!,
               :rm,
               :rm!,
               :rm_rf]

  @double_file_funcs [:cp,
                      :cp!,
                      :cp_r,
                      :cp_r!,
                      :ln,
                      :ln!,
                      :ln_s,
                      :ln_s!]

  def run(fun, filename) do
    severity = if String.ends_with?(filename, "_controller.ex"), do: false, else: :low

    Enum.each @file_funcs ++ @double_file_funcs, fn(file_func) ->
      {findings, params, {fun_name, [{_, line_no}]}} = parse_def(fun, file_func)
      Enum.each findings, fn {finding, var} ->
        Utils.add_finding(line_no, filename, fun, fun_name,
                          var, Utils.get_sev(params, var, severity),
                          finding, "Directory Traversal in `File.#{file_func}`")
      end
    end

    Enum.each @double_file_funcs, fn(file_func) ->
      {findings, params, {fun_name, [{_, line_no}]}} = parse_second_def(fun, file_func)
      Enum.each findings, fn {finding, var} ->
        Utils.add_finding(line_no, filename, fun, fun_name,
                          var, Utils.get_sev(params, var, severity),
                          finding, "Directory Traversal in `File.#{file_func}`")
      end
    end
  end

  def parse_def(fun, type) do
    Utils.get_fun_vars_and_meta(fun, 0, type, [:File])
  end

  def parse_second_def(fun, type) do
    Utils.get_fun_vars_and_meta(fun, 1, type, [:File])
  end

  def details() do
    Sobelow.Traversal.details()
  end
end