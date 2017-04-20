defmodule Sobelow.XSS.SendResp do
  alias Sobelow.Utils

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

  def parse_send_resp_def(fun) do
    {params, {fun_name, line_no}} = Utils.get_fun_declaration(fun)

    resps = Utils.get_funs_of_type(fun, :send_resp)
    |> Enum.map(&Utils.extract_opts/1)

    is_html = Utils.get_funs_of_type(fun, :put_resp_content_type)
    |> Enum.any?(&Utils.is_content_type_html/1)

    {resps, is_html, params, {fun_name, line_no}}
  end

  defp print_resp_finding(line_no, con, fun_name, fun, var, severity) do
    {color, confidence} = case severity do
      :high -> {IO.ANSI.red(), "High"}
      :medium -> {IO.ANSI.yellow(), "Medium"}
      :low -> {IO.ANSI.green(), "Low"}
    end
    IO.puts color <> "XSS in `send_resp` - #{confidence} Confidence" <> IO.ANSI.reset()
    IO.puts "File: #{con} - #{fun_name}:#{line_no}"
    IO.puts "Variable: #{var}"
    if Sobelow.get_env(:with_code), do: Utils.print_code(fun, var, :send_resp)
    IO.puts "\n-----------------------------------------------\n"
  end
end