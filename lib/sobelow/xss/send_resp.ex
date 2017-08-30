defmodule Sobelow.XSS.SendResp do
  alias Sobelow.Utils
  use Sobelow.Finding

  def run(fun, filename) do
    {ref_vars, is_html, params, {fun_name, [{_, line_no}]}} = parse_def(fun)

    Enum.each ref_vars, fn var ->
      if is_list(var) do
        Enum.each var, fn {finding, v} ->
          if (Enum.member?(params, v) || v === "conn.params") && is_html do
            print_resp_finding(line_no, filename, fun_name, fun, v, :high, finding)
          end

          if is_html && !Enum.member?(params, v) do
            print_resp_finding(line_no, filename, fun_name, fun, v, :medium, finding)
          end
        end
      end
    end
  end

  def parse_def(fun) do
    {vars, params, {fun_name, line_no}} = Utils.get_fun_vars_and_meta(fun, 2, :send_resp)
    {aliased_vars,_,_} = Utils.get_fun_vars_and_meta(fun, 2, :send_resp, [:Plug, :Conn])

    is_html = Utils.get_funs_of_type(fun, :put_resp_content_type)
    |> Kernel.++(Utils.get_aliased_funs_of_type(fun, :put_resp_content_type, [:Plug, :Conn]))
    |> Enum.any?(&Utils.is_content_type_html/1)

    {vars ++ aliased_vars, is_html, params, {fun_name, line_no}}
  end

  def details() do
    Sobelow.XSS.details()
  end

  defp print_resp_finding(line_no, filename, fun_name, fun, var, severity, finding) do
    Utils.add_finding(line_no, filename, fun,
                      fun_name, var, severity, finding,
                      "XSS in `send_resp`")
  end
end
