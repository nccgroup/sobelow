defmodule Sobelow.CI.OS do
  alias Sobelow.Utils
  use Sobelow.Finding

  def run(fun, filename) do
    severity = if String.ends_with?(filename, "_controller.ex"), do: false, else: :low
    {vars, params, {fun_name, [{_, line_no}]}} = parse_def(fun)

    Enum.each vars, fn var ->
      add_finding(line_no, filename, fun_name,
                  fun, var, Utils.get_sev(params, var, severity))
    end
  end

  def parse_def(fun) do
    Utils.get_erlang_fun_vars_and_meta(fun, 0, :cmd, :os)
  end

  def add_finding(line_no, filename, fun_name, fun, var, severity) do
    Utils.add_finding(line_no, filename, fun,
                      fun_name, var, severity,
                      "Command Injection in `:os.cmd`", :cmd, :os)
  end

  def get_details() do
    Sobelow.CI.details()
  end
end