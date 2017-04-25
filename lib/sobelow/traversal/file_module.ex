defmodule Sobelow.Traversal.FileModule do
  alias Sobelow.Utils
  use Sobelow.Finding

  def run(fun, filename) do
    {vars, params, {fun_name, [{_, line_no}]}} = parse_file_def(fun, :read)
    severity = if String.ends_with?(filename, "_controller.ex"), do: false, else: :low

    Enum.each vars, fn var ->
      if Enum.member?(params, var) || var === "conn.params" do
        print_file_finding(line_no, filename, fun_name, fun, var, :read, severity || :high)
      else
        print_file_finding(line_no, filename, fun_name, fun, var, :read, severity || :medium)
      end
    end

    {vars, params, {fun_name, [{_, line_no}]}} = parse_file_def(fun, :write)

    Enum.each vars, fn var ->
      if Enum.member?(params, var) || var === "conn.params" do
        print_file_finding(line_no, filename, fun_name, fun, var, :write, severity || :high)
      else
        print_file_finding(line_no, filename, fun_name, fun, var, :write, severity || :medium)
      end
    end

    {vars, params, {fun_name, [{_, line_no}]}} = parse_file_def(fun, :rm)

    Enum.each vars, fn var ->
      if Enum.member?(params, var) || var === "conn.params" do
        print_file_finding(line_no, filename, fun_name, fun, var, :rm, severity || :high)
      else
        print_file_finding(line_no, filename, fun_name, fun, var, :rm, severity || :medium)
      end
    end

    {vars, params, {fun_name, [{_, line_no}]}} = parse_file_def(fun, :read!)

    Enum.each vars, fn var ->
      if Enum.member?(params, var) || var === "conn.params" do
        print_file_finding(line_no, filename, fun_name, fun, var, :read!, severity || :high)
      else
        print_file_finding(line_no, filename, fun_name, fun, var, :read!, severity || :medium)
      end
    end

    {vars, params, {fun_name, [{_, line_no}]}} = parse_file_def(fun, :write!)

    Enum.each vars, fn var ->
      if Enum.member?(params, var) || var === "conn.params" do
        print_file_finding(line_no, filename, fun_name, fun, var, :write!, severity || :high)
      else
        print_file_finding(line_no, filename, fun_name, fun, var, :write!, severity || :medium)
      end
    end

    {vars, params, {fun_name, [{_, line_no}]}} = parse_file_def(fun, :rm!)

    Enum.each vars, fn var ->
      if Enum.member?(params, var) || var === "conn.params" do
        print_file_finding(line_no, filename, fun_name, fun, var, :rm!, severity || :high)
      else
        print_file_finding(line_no, filename, fun_name, fun, var, :rm!, severity || :medium)
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

  def print_file_finding(line_no, con, fun_name, fun, var, type, severity) do
    {color, confidence} = case severity do
      :high -> {IO.ANSI.red(), "High"}
      :medium -> {IO.ANSI.yellow(), "Medium"}
      :low -> {IO.ANSI.green(), "Low"}
    end
    IO.puts color <> "Directory Traversal in `File.#{type}` - #{confidence} Confidence" <> IO.ANSI.reset()
    IO.puts "File: #{con} - #{fun_name}:#{line_no}"
    IO.puts "Variable: #{var}"
    if Sobelow.get_env(:with_code), do: Utils.print_code(fun, var, type)
    IO.puts "\n-----------------------------------------------\n"
  end

  def get_details() do
    Sobelow.Traversal.details()
  end
end