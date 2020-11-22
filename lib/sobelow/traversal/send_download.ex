defmodule Sobelow.Traversal.SendDownload do
  @uid 20
  @finding_type "Traversal.SendDownload: Directory Traversal in `send_download`"

  use Sobelow.Finding

  def run(fun, meta_file) do
    confidence = if !meta_file.is_controller?, do: :low

    Finding.init(@finding_type, meta_file.filename, confidence)
    |> Finding.multi_from_def(fun, parse_def(fun))
    |> Enum.each(&Print.add_finding(&1))
  end

  ## send_download(conn, {:file, path})
  def parse_def(fun) do
    {findings, params, {fun_name, line_no}} =
      Parse.get_fun_vars_and_meta(fun, 1, :send_download, :Controller)

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

  defp download_type_binary?({{:., _, [{_, _, _}, :send_download]}, _, opts}),
    do: type_binary?(opts)

  defp type_binary?([_, {:binary, _}, _]), do: true
  defp type_binary?([_, {:binary, _}]), do: true
  defp type_binary?([{:binary, _}]), do: true
  defp type_binary?([{:binary, _}, _]), do: true
  defp type_binary?(_), do: false
end
