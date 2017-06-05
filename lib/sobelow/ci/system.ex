defmodule Sobelow.CI.System do
  alias Sobelow.Utils
  use Sobelow.Finding

  def run(fun, filename) do
    severity = if String.ends_with?(filename, "_controller.ex"), do: false, else: :low
    {vars, params, {fun_name, [{_, line_no}]}} = parse_system_def(fun, :cmd)

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

  def parse_system_def(fun, type) do
    Utils.get_fun_vars_and_meta(fun, 0, type, [:System])
  end

  def print_sys_finding(line_no, filename, fun_name, fun, var, severity) do
    Utils.print_finding_metadata(line_no, filename, fun,
                                   fun_name, var, severity,
                                   "Command Injection in `System.cmd`", :cmd, [:System])
  end

  def get_details() do
    Sobelow.CI.details()
  end
end