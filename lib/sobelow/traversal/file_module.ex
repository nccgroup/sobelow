defmodule Sobelow.Traversal.FileModule do
  alias Sobelow.Utils

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
    severity = if String.ends_with?(filename, "_controller.ex"), do: false, else: :low

    Enum.each vars, fn var ->
      if Enum.member?(params, var) || var === "conn.params" do
        print_file_finding(line_no, filename, fun_name, fun, var, :write, severity || :high)
      else
        print_file_finding(line_no, filename, fun_name, fun, var, :write, severity || :medium)
      end
    end
  end

  def parse_file_def(fun, type) do
    {params, {fun_name, line_no}} = Utils.get_fun_declaration(fun)

    resps = Utils.get_aliased_funs_of_type(fun, type, [:File])
    |> Enum.map(&Utils.extract_opts/1)
    |> List.flatten

    {resps, params, {fun_name, line_no}}
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
end