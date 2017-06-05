defmodule Sobelow.XSS.SendResp do
  alias Sobelow.Utils
  use Sobelow.Finding

  def run(fun, filename) do
    {ref_vars, is_html, params, {fun_name, [{_, line_no}]}} = parse_send_resp_def(fun)

    Enum.each ref_vars, fn var ->
      if is_list(var) do
        Enum.each var, fn v ->
          if (Enum.member?(params, v) || v === "conn.params") && is_html do
            Sobelow.log_finding("XSS", :high)
            print_resp_finding(line_no, filename, fun_name, fun, v, :high)
          end

          if is_html && !Enum.member?(params, v) do
            Sobelow.log_finding("XSS", :medium)
            print_resp_finding(line_no, filename, fun_name, fun, v, :medium)
          end
        end
      else
        if (Enum.member?(params, var) || var === "conn.params") && is_html do
          Sobelow.log_finding("XSS", :high)
          print_resp_finding(line_no, filename, fun_name, fun, var, :high)
        end

        if is_html && !Enum.member?(params, var) && var != "conn.params" do
          Sobelow.log_finding("XSS", :medium)
          print_resp_finding(line_no, filename, fun_name, fun, var, :medium)
        end
      end
    end
  end

  defp parse_send_resp_def(fun) do
    {vars, params, {fun_name, line_no}} = Utils.get_fun_vars_and_meta(fun, 2, :send_resp)
    {aliased_vars,_,_} = Utils.get_fun_vars_and_meta(fun, 2, :send_resp, [:Plug, :Conn])

    is_html = Utils.get_funs_of_type(fun, :put_resp_content_type)
    |> Enum.any?(&Utils.is_content_type_html/1)

    {vars ++ aliased_vars, is_html, params, {fun_name, line_no}}
  end

  def get_details() do
    Sobelow.XSS.details()
  end

  defp print_resp_finding(line_no, filename, fun_name, fun, var, severity) do
    Utils.print_finding_metadata(line_no, filename, fun,
                                   fun_name, var, severity,
                                   "XSS in `send_resp`", :send_resp, [:Plug, :Conn])
  end
end
