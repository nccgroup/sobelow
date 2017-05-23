defmodule Sobelow.XSS.SendResp do
  alias Sobelow.Utils
  use Sobelow.Finding

  def run(fun, filename) do
    {ref_vars, is_html, params, {fun_name, [{_, line_no}]}} = parse_send_resp_def(fun)

    Enum.each ref_vars, fn var ->
      if is_list(var) do
        Enum.each var, fn v ->
          if (Enum.member?(params, v) || v === "conn.params") && is_html do
            print_resp_finding(line_no, filename, fun_name, fun, v, :high)
          end

          if is_html && !Enum.member?(params, v) do
            print_resp_finding(line_no, filename, fun_name, fun, v, :medium)
          end
        end
      else
        if (Enum.member?(params, var) || var === "conn.params") && is_html do
          print_resp_finding(line_no, filename, fun_name, fun, var, :high)
        end

        if is_html && !Enum.member?(params, var) && var != "conn.params" do
          print_resp_finding(line_no, filename, fun_name, fun, var, :medium)
        end
      end
    end
  end

  defp parse_send_resp_def(fun) do
    {params, {fun_name, line_no}} = Utils.get_fun_declaration(fun)

    pipefuns = Utils.get_pipe_funs(fun)
    |> Enum.map(fn {_, _, opts} -> Enum.at(opts, 1) end)
    |> Enum.flat_map(&Utils.get_funs_of_type(&1, :send_resp))

    pipevars = pipefuns
    |> Enum.map(&Utils.extract_opts(&1, 1))
    |> List.flatten

    vars = Utils.get_funs_of_type(fun, :send_resp) -- pipefuns
    |> Enum.map(&Utils.extract_opts(&1, 2))
    |> List.flatten

    is_html = Utils.get_funs_of_type(fun, :put_resp_content_type)
    |> Enum.any?(&Utils.is_content_type_html/1)

    {aliased_vars, _, _} = parse_aliased_send_resp_def(fun)

    {vars ++ pipevars ++ aliased_vars, is_html, params, {fun_name, line_no}}
  end

  defp parse_aliased_send_resp_def(fun) do
    {params, {fun_name, line_no}} = Utils.get_fun_declaration(fun)

    pipefuns = Utils.get_pipe_funs(fun)
    |> Enum.map(fn {_, _, opts} -> Enum.at(opts, 1) end)
    |> Enum.flat_map(&Utils.get_aliased_funs_of_type(&1, :send_resp, [:Plug, :Conn]))

    pipevars = pipefuns
    |> Enum.map(&Utils.extract_opts(&1, 1))
    |> List.flatten

    aliased_vars = Utils.get_aliased_funs_of_type(fun, :send_resp, [:Plug, :Conn]) -- pipefuns
    |> Enum.map(&Utils.extract_opts(&1, 2))
    |> List.flatten

    {aliased_vars ++ pipevars, params, {fun_name, line_no}}
  end

  def get_details() do
    Sobelow.XSS.details()
  end

  defp print_resp_finding(line_no, filename, fun_name, fun, var, severity) do
    Utils.print_finding_metadata(line_no, filename, fun,
                                   fun_name, var, severity,
                                   "XSS in `send_resp`", :send_resp)
  end
end