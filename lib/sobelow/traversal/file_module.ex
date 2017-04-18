defmodule Sobelow.Traversal.FileModule do
  alias Sobelow.Utils
  alias Sobelow.Traversal

  def run(fun, filename) do
    {vars, params, {fun_name, [{_, line_no}]}} = Utils.parse_file_read_def(fun)
    filename = String.replace_prefix(filename, "/", "")
    severity = if String.ends_with?(filename, "_controller.ex"), do: false, else: :low

    Enum.each vars, fn var ->
      if Enum.member?(params, var) || var === "conn.params" do
        Traversal.print_file_finding(line_no, filename, fun_name, fun, var, :read, severity || :high)
      else
        Traversal.print_file_finding(line_no, filename, fun_name, fun, var, :read, severity || :medium)
      end
    end
  end
end