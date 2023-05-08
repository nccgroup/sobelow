defmodule Sobelow.Traversal.SendFile do
  @moduledoc """
  # Directory Traversal in `send_file`

  This submodule checks for directory traversal vulnerabilities in the
  `send_file` function.

  Ensure that the path passed to `send_file` is not user-controlled.

  Send File checks can be ignored with the following command:

      $ mix sobelow -i Traversal.SendFile
  """
  @uid 21
  @finding_type "Traversal.SendFile: Directory Traversal in `send_file`"

  use Sobelow.Finding

  def run(fun, meta_file) do
    confidence = if !meta_file.is_controller?, do: :low

    Finding.init(@finding_type, meta_file.filename, confidence)
    |> Finding.multi_from_def(fun, parse_def(fun))
    |> Enum.each(&Print.add_finding(&1))
  end

  ## send_file(conn, status, file, offset \\ 0, length \\ :all)
  def parse_def(fun) do
    Parse.get_fun_vars_and_meta(fun, 2, :send_file, :Conn)
  end
end
