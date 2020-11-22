defmodule Sobelow.Traversal.FileModule do
  @uid 19
  @finding_type "Traversal.FileModule: Directory Traversal in `File` function"

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
    confidence = if !meta_file.is_controller?, do: :low

    Enum.each(@file_funcs ++ @double_file_funcs, fn file_func ->
      "Traversal.FileModule: Directory Traversal in `File.#{file_func}`"
      |> Finding.init(meta_file.filename, confidence)
      |> Finding.multi_from_def(fun, parse_def(fun, file_func))
      |> Enum.each(&Print.add_finding(&1))
    end)

    Enum.each(@double_file_funcs, fn file_func ->
      "Traversal.FileModule: Directory Traversal in `File.#{file_func}`"
      |> Finding.init(meta_file.filename, confidence)
      |> Finding.multi_from_def(fun, parse_second_def(fun, file_func))
      |> Enum.each(&Print.add_finding(&1))
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
