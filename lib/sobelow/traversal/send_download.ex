defmodule Sobelow.Traversal.SendDownload do
  alias Sobelow.Utils
  use Sobelow.Finding
  @finding_type "Directory Traversal in `send_download`"

  def run(fun, meta_file) do
    severity = if meta_file.is_controller?, do: false, else: :low
    {findings, params, {fun_name, [{_, line_no}]}} = parse_def(fun)

    Enum.each findings, fn {finding, var} ->
      if not download_type_binary?(finding) do
        Utils.add_finding(line_no, meta_file.filename, fun, fun_name,
                          var, Utils.get_sev(params, var, severity),
                          finding, @finding_type)
      end
    end
  end

  ## send_download(conn, {:file, path})
  defp parse_def(fun) do
    Utils.get_fun_vars_and_meta(fun, 1, :send_download)
  end

  def details() do
    Sobelow.Traversal.details()
  end

  defp download_type_binary?({:send_download, _, opts}), do: type_binary?(opts)
  defp type_binary?([_, {:binary, _}]), do: true
  defp type_binary?([{:binary, _}]), do: true
  defp type_binary?(_), do: false
end