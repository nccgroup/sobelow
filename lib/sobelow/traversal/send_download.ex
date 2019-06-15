defmodule Sobelow.Traversal.SendDownload do
  alias Sobelow.{Parse, Print}
  use Sobelow.Finding
  @finding_type "Traversal.SendDownload: Directory Traversal in `send_download`"

  def run(fun, meta_file) do
    severity = if meta_file.is_controller?, do: false, else: :low
    {findings, params, {fun_name, line_no}} = parse_def(fun)

    Enum.each(findings, fn {finding, var} ->
      Print.add_finding(
        line_no,
        meta_file.filename,
        fun,
        fun_name,
        var,
        Print.get_sev(params, var, severity),
        finding,
        @finding_type
      )
    end)
  end

  ## send_download(conn, {:file, path})
  def parse_def(fun) do
    {findings, params, {fun_name, [{_, line_no}]}} =
      Parse.get_fun_vars_and_meta(fun, 1, :send_download)

    findings =
      Enum.reject(findings, fn {finding, _var} ->
        download_type_binary?(finding)
      end)

    {findings, params, {fun_name, line_no}}
  end

  def details() do
    Sobelow.Traversal.details()
  end

  defp download_type_binary?({:send_download, _, opts}), do: type_binary?(opts)
  defp type_binary?([_, {:binary, _}, _]), do: true
  defp type_binary?([_, {:binary, _}]), do: true
  defp type_binary?([{:binary, _}]), do: true
  defp type_binary?(_), do: false
end
