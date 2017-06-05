defmodule Sobelow.CI.OS do
  alias Sobelow.Utils
  use Sobelow.Finding

  def run(fun, filename) do
    severity = if String.ends_with?(filename, "_controller.ex"), do: false, else: :low
    {vars, params, {fun_name, [{_, line_no}]}} = parse_os_def(fun, :cmd)

    Enum.each vars, fn var ->
      if Enum.member?(params, var) || var === "conn.params" do
        log_finding("Command Injection", severity || :high)
        print_sys_finding(line_no, filename, fun_name, fun, var, severity || :high)
      else
        log_finding("Command Injection", severity || :medium)
        print_sys_finding(line_no, filename, fun_name, fun, var, severity || :medium)
      end
    end
  end

  def parse_os_def(fun, type) do
    {params, {fun_name, line_no}} = Utils.get_fun_declaration(fun)

    pipefuns = Utils.get_pipe_funs(fun)
    |> Enum.map(fn {_, _, opts} -> Enum.at(opts, 1) end)
    |> Enum.flat_map(&Utils.get_erlang_aliased_funs_of_type(&1, type, :os))

    pipeos = Enum.flat_map(pipefuns, &Utils.get_pipe_val(fun, &1))
    |> List.flatten

    osfuns = Utils.get_erlang_aliased_funs_of_type(fun, type, :os) -- pipeos
    |> Enum.map(&Utils.extract_opts(&1, 0))
    |> List.flatten

    {osfuns ++ pipeos, params, {fun_name, line_no}}
  end

  def print_sys_finding(line_no, filename, fun_name, fun, var, severity) do
    Utils.print_finding_metadata(line_no, filename, fun,
                                   fun_name, var, severity,
                                   "Command Injection in `:os.cmd`", :cmd, :os)
  end

  def get_details() do
    Sobelow.CI.details()
  end
end