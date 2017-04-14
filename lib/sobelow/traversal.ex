defmodule Sobelow.Traversal do
  alias Sobelow.Utils

  def fetch(web_root) do
    # Used for testing until I create a real broken demo app.
    # web_root = "../hexpm/lib/hexpm/web/"

    IO.puts IO.ANSI.cyan_background() <>
      IO.ANSI.black() <>
      "Searching for Directory Traversal" <>
      IO.ANSI.reset()
    IO.puts "\n-----------------------------------------------\n"

    Utils.all_controllers(web_root <> "controllers/")
    |> Enum.each(fn cont -> find_vulnerable_ref(cont, web_root <> "controllers/") end)
  end

  defp find_vulnerable_ref(controller_path, controller_root) do
    def_funs = Utils.get_def_funs(controller_root <> controller_path)

    send_file_funs = Enum.map(def_funs, &Utils.parse_send_file_def(&1))
    |> Enum.reject(fn {vars, _, _} -> Enum.empty?(vars) end)

    controller = String.replace_suffix(controller_path, "_controller.ex", "")
    con = String.replace_prefix(controller, "/", "")

    Enum.each(send_file_funs, fn {vars, params, {fun_name, [{_, line_no}]}} ->
      Enum.each(vars, fn var ->
        if Enum.member?(params, var) do
          print_finding(line_no, con, fun_name, var, :high)
        else
          print_finding(line_no, con, fun_name, var, :medium)
        end
      end)
    end)
  end

  defp print_finding(line_no, con, fun_name, var, :high) do
    IO.puts IO.ANSI.red() <> "Directory Traversal in `send_file` - High Confidence" <> IO.ANSI.reset()
    IO.puts "File: #{con} - #{fun_name}:#{line_no}"
    IO.puts "Variable: #{var}"
    IO.puts "\n-----------------------------------------------\n"
  end

  defp print_finding(line_no, con, fun_name, var, :medium) do
    IO.puts IO.ANSI.yellow() <> "Directory Traversal in `send_file` - Medium Confidence" <> IO.ANSI.reset()
    IO.puts "File: #{con} - #{fun_name}:#{line_no}"
    IO.puts "Variable: #{var}"
    IO.puts "\n-----------------------------------------------\n"
  end
end