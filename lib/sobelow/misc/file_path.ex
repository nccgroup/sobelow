defmodule Sobelow.Misc.FilePath do
  @moduledoc """
  # Insecure use of `File` and `Path`

  In Elixir, `File` methods are null-terminated, while `Path`
  methods are not.

  `File/Path` checks can be ignored with the following command:

      $ mix sobelow -i Misc.FilePath
  """
  alias Sobelow.Utils
  use Sobelow.Finding

  def run(fun, filename) do
    {vars, params, {fun_name, [{_, line_no}]}} = parse_def(fun)

    Enum.each vars, fn var ->
      if Enum.member?(params, var) || var === "conn.params" do
        Sobelow.log_finding("Insecure use of `File` and `Path`", :medium)
        print_finding(line_no, filename, fun_name, fun, var, :medium)
      else
        Sobelow.log_finding("Insecure use of `File` and `Path`", :low)
        print_finding(line_no, filename, fun_name, fun, var, :low)
      end
    end
  end

  defp print_finding(line_no, filename, fun_name, fun, var, severity) do
    Utils.print_file_path_finding_metadata(line_no, filename, fun,
                                   fun_name, var, severity)
  end

  def parse_def(fun) do
    {params, {fun_name, line_no}} = Utils.get_fun_declaration(fun)

    file_assigns = Utils.get_assigns_from(fun, [:File])
    path_assigns = Utils.get_assigns_from(fun, [:Path])

    path_vars = Utils.get_funs_by_module(fun, [:Path])
    |> Enum.map(&Utils.extract_opts(&1, 0))
    |> List.flatten

    file_vars = Utils.get_funs_by_module(fun, [:File])
    |> Enum.map(&Utils.extract_opts(&1, 0))
    |> List.flatten

    shared_path =
      Enum.filter(path_vars, fn var ->
        Enum.member?(file_assigns, var)
      end)

    shared_file =
      Enum.filter(file_vars, fn var ->
        Enum.member?(path_assigns, var)
      end)
#
#    {shared_file ++ shared_path, params, {fun_name, line_no}}
    vars = Enum.filter(file_vars, fn var ->
      Enum.member?(path_vars, var)
    end)
    {vars ++ shared_file ++ shared_path, params, {fun_name, line_no}}
  end
end