defmodule Sobelow.CI.System do
  alias Sobelow.Utils
  use Sobelow.Finding

  def run(fun, filename) do
    severity = if String.ends_with?(filename, "_controller.ex"), do: false, else: :low
    {vars, params, {fun_name, [{_, line_no}]}} = parse_system_def(fun, :cmd)

    Enum.each vars, fn var ->
      if Enum.member?(params, var) || var === "conn.params" do
        print_sys_finding(line_no, filename, fun_name, fun, var, severity || :high)
      else
        print_sys_finding(line_no, filename, fun_name, fun, var, severity || :medium)
      end
    end
  end

  def parse_system_def(fun, type) do
    {params, {fun_name, line_no}} = Utils.get_fun_declaration(fun)

    pipefuns = Utils.get_pipe_funs(fun)
    |> Enum.map(fn {_, _, opts} -> Enum.at(opts, 1) end)
    |> Enum.flat_map(&Utils.get_aliased_funs_of_type(&1, type, [:System]))

    pipesys = Enum.flat_map(pipefuns, &Utils.get_pipe_val(fun, &1))
    |> List.flatten

    sys = Utils.get_aliased_funs_of_type(fun, type, [:System]) -- pipesys
    |> Enum.map(&Utils.extract_opts(&1, 0))
    |> List.flatten

    {sys ++ pipesys, params, {fun_name, line_no}}
  end

  def print_sys_finding(line_no, con, fun_name, fun, var, severity) do
    {color, confidence} = case severity do
      :high -> {IO.ANSI.red(), "High"}
      :medium -> {IO.ANSI.yellow(), "Medium"}
      :low -> {IO.ANSI.green(), "Low"}
    end
    IO.puts color <> "Command Injection in `System.cmd` - #{confidence} Confidence" <> IO.ANSI.reset()
    IO.puts "File: #{con} - #{fun_name}:#{line_no}"
    IO.puts "Variable: #{var}"
    if Sobelow.get_env(:with_code), do: Utils.print_code(fun, var, :cmd)
    IO.puts "\n-----------------------------------------------\n"
  end

  def get_details() do
    Sobelow.CI.details()
  end
end