defmodule Sobelow.Traversal.SendFile do
  alias Sobelow.Utils

  def run(fun, filename) do
    {vars, params, {fun_name, [{_, line_no}]}} = parse_send_file_def(fun)
    filename = String.replace_prefix(filename, "/", "")
    severity = if String.ends_with?(filename, "_controller.ex"), do: false, else: :low

    if String.ends_with?(filename, "_controller.ex") do
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
end