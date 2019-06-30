defmodule Sobelow.Traversal.SendFile do
  use Sobelow.Finding
  @finding_type "Traversal.SendFile: Directory Traversal in `send_file`"

  def run(fun, meta_file) do
    confidence = if !meta_file.is_controller?, do: :low

    Finding.init(@finding_type, meta_file.filename, confidence)
    |> Finding.multi_from_def(fun, parse_def(fun))
    |> Enum.each(&Print.add_finding(&1))
  end

  ## send_file(conn, status, file, offset \\ 0, length \\ :all)
  defp parse_def(fun) do
    {files, params, {fun_name, line_no}} = Parse.get_fun_vars_and_meta(fun, 2, :send_file)
    {aliased_files, _, _} = Parse.get_fun_vars_and_meta(fun, 2, :send_file, :Conn)

    {files ++ aliased_files, params, {fun_name, line_no}}
  end

  def details() do
    Sobelow.Traversal.details()
  end
end
