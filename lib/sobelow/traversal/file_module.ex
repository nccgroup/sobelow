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

  def run(fun, filename) do
    severity = if String.ends_with?(filename, "_controller.ex"), do: false, else: :low

    Enum.each @file_funcs, fn(file_func) ->
      {vars, params, {fun_name, [{_, line_no}]}} = parse_file_def(fun, file_func)

      Enum.each vars, fn var ->
        if Enum.member?(params, var) || var === "conn.params" do
          print_file_finding(line_no, filename, fun_name, fun, var, file_func, severity || :high)
        else
          print_file_finding(line_no, filename, fun_name, fun, var, file_func, severity || :medium)
        end
      end
    end

  end

  def parse_file_def(fun, type) do
    {params, {fun_name, line_no}} = Utils.get_fun_declaration(fun)

    pipefuns = Utils.get_pipe_funs(fun)
    |> Enum.map(fn {_, _, opts} -> Enum.at(opts, 1) end)
    |> Enum.flat_map(&Utils.get_aliased_funs_of_type(&1, type, [:File]))

    pipefiles = Enum.flat_map(pipefuns, &Utils.get_pipe_val(fun, &1))
    |> List.flatten
    # Can extract_opts at idx 0, because File functions path is
    # always the first parameter.
    files = Utils.get_aliased_funs_of_type(fun, type, [:File]) -- pipefuns
    |> Enum.map(&Utils.extract_opts(&1, 0))
    |> List.flatten

    {files ++ pipefiles, params, {fun_name, line_no}}
  end

  def print_file_finding(line_no, filename, fun_name, fun, var, type, severity) do
    Utils.print_finding_metadata(line_no, filename, fun,
                                   fun_name, var, severity,
                                   "Directory Traversal in `File.#{type}`", type, [:File])
  end

  def get_details() do
    Sobelow.Traversal.details()
  end
end