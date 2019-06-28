defmodule Sobelow.Traversal.FileModule do
  alias Sobelow.{Parse, Print}
  use Sobelow.Finding

  @file_funcs [
    :read,
    :read!,
    :write,
    :write!,
    :rm,
    :rm!,
    :rm_rf,
    :open,
    :open!,
    :chmod,
    :chmod!,
    :chown,
    :chown!,
    :mkdir,
    :mkdir!,
    :mkdir_p,
    :mkdir_p!
  ]
  @double_file_funcs [:cp, :copy, :cp!, :copy!, :cp_r, :cp_r!, :ln, :ln!, :ln_s, :ln_s!]

  def run(fun, meta_file) do
    severity = if meta_file.is_controller?, do: false, else: :low

    Enum.each(@file_funcs ++ @double_file_funcs, fn file_func ->
      {findings, params, {fun_name, line_no}} = parse_def(fun, file_func)

      Enum.each(findings, fn {finding, var} ->
        Print.add_finding(
          line_no,
          meta_file.filename,
          fun,
          fun_name,
          var,
          Print.get_sev(params, var, severity),
          finding,
          "Traversal.FileModule: Directory Traversal in `File.#{file_func}`"
        )
      end)
    end)

    Enum.each(@double_file_funcs, fn file_func ->
      {findings, params, {fun_name, line_no}} = parse_second_def(fun, file_func)

      Enum.each(findings, fn {finding, var} ->
        Print.add_finding(
          line_no,
          meta_file.filename,
          fun,
          fun_name,
          var,
          Print.get_sev(params, var, severity),
          finding,
          "Traversal.FileModule: Directory Traversal in `File.#{file_func}`"
        )
      end)
    end)
  end

  def parse_def(fun, type) do
    Parse.get_fun_vars_and_meta(fun, 0, type, [:File])
  end

  def parse_second_def(fun, type) do
    Parse.get_fun_vars_and_meta(fun, 1, type, [:File])
  end

  def details() do
    Sobelow.Traversal.details()
  end
end
