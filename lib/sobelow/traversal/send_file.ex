defmodule Sobelow.Traversal.SendFile do
  alias Sobelow.Utils
  alias Sobelow.Traversal

  def run(fun, filename) do
    {vars, params, {fun_name, [{_, line_no}]}} = parse_send_file_def(fun)
    filename = String.replace_prefix(filename, "/", "")
    severity = if String.ends_with?(filename, "_controller.ex"), do: false, else: :low

    if String.ends_with?(filename, "_controller.ex") do
      Enum.each vars, fn var ->
        if Enum.member?(params, var) || var === "conn.params" do
          Traversal.print_finding(line_no, filename, fun_name, fun, var, severity || :high)
        else
          Traversal.print_finding(line_no, filename, fun_name, fun, var, severity || :medium)
        end
      end
    end
  end

  ## send_file(conn, status, file, offset \\ 0, length \\ :all)
  ##
  ## send_file has optional params, so the parameter we care about
  ## for traversal won't be at a definite location. This is a
  ## simple solution to the problem.
  defp parse_send_file_def(fun) do
    {params, {fun_name, line_no}} = Utils.get_fun_declaration(fun)

    pipefiles = Utils.get_funs_of_type(fun, :|>)
    |> Enum.map(fn {_, _, opts} -> Enum.at(opts, 1) end)
    |> Enum.flat_map(&Utils.get_funs_of_type(&1, :send_file))
    |> Enum.map(&Utils.extract_opts({:pipe, &1}))
    |> List.flatten

    files = Utils.get_funs_of_type(fun, :send_file) -- pipefiles
    |> Enum.map(&Utils.extract_opts/1)
    |> List.flatten


    {files ++ pipefiles, params, {fun_name, line_no}}
  end
end