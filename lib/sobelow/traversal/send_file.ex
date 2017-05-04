defmodule Sobelow.Traversal.SendFile do
  alias Sobelow.Utils
  use Sobelow.Finding

  def run(fun, filename) do
    severity = if String.ends_with?(filename, "_controller.ex"), do: false, else: :low

    # If the file is a controller, check for `send_file` as well as
    # `Plug.Conn.send_file`. If it is not a controller, look for
    # `Plug.Conn.send_file` only.
    if String.ends_with?(filename, "_controller.ex") do
      {vars, params, {fun_name, [{_, line_no}]}} = parse_send_file_def(fun)
      Enum.each vars, fn var ->
        if Enum.member?(params, var) || var === "conn.params" do
          print_finding(line_no, filename, fun_name, fun, var, severity || :high)
        else
          print_finding(line_no, filename, fun_name, fun, var, severity || :medium)
        end
      end
    else
      {vars, params, {fun_name, [{_, line_no}]}} = parse_aliased_send_file_def(fun)
      Enum.each vars, fn var ->
        if Enum.member?(params, var) || var === "conn.params" do
          print_finding(line_no, filename, fun_name, fun, var, severity || :high)
        else
          print_finding(line_no, filename, fun_name, fun, var, severity || :medium)
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

    pipefuns = Utils.get_pipe_funs(fun)
    |> Enum.map(fn {_, _, opts} -> Enum.at(opts, 1) end)
    |> Enum.flat_map(&Utils.get_funs_of_type(&1, :send_file))

    pipefiles = pipefuns
    |> Enum.map(&Utils.extract_opts({:pipe, &1}))
    |> List.flatten

    files = Utils.get_funs_of_type(fun, :send_file) -- pipefuns
    |> Enum.map(&Utils.extract_opts/1)
    |> List.flatten

    {aliased_files, _, _} = parse_aliased_send_file_def(fun)

    {files ++ pipefiles ++ aliased_files, params, {fun_name, line_no}}
  end

  defp parse_aliased_send_file_def(fun) do
    {params, {fun_name, line_no}} = Utils.get_fun_declaration(fun)

    pipefuns = Utils.get_pipe_funs(fun)
    |> Enum.map(fn {_, _, opts} -> Enum.at(opts, 1) end)
    |> Enum.flat_map(&Utils.get_aliased_funs_of_type(&1, :send_file, [:Plug, :Conn]))

    pipefiles = pipefuns
    |> Enum.map(&Utils.extract_opts({:pipe, &1}))
    |> List.flatten

    aliased_files = Utils.get_aliased_funs_of_type(fun, :send_file, [:Plug, :Conn]) -- pipefuns
    |> Enum.map(&Utils.extract_opts/1)
    |> List.flatten

    {aliased_files ++ pipefiles, params, {fun_name, line_no}}
  end

  def print_finding(line_no, con, fun_name, fun, var, severity) do
    {color, confidence} = case severity do
      :high -> {IO.ANSI.red(), "High"}
      :medium -> {IO.ANSI.yellow(), "Medium"}
      :low -> {IO.ANSI.green(), "Low"}
    end
    IO.puts color <> "Directory Traversal in `send_file` - #{confidence} Confidence" <> IO.ANSI.reset()
    IO.puts "File: #{con} - #{fun_name}:#{line_no}"
    IO.puts "Variable: #{var}"
    if Sobelow.get_env(:with_code), do: Utils.print_code(fun, var, :send_file)
    IO.puts "\n-----------------------------------------------\n"
  end

  def get_details() do
    Sobelow.Traversal.details()
  end
end