defmodule SobelowTest.RCE.CodeModuleTest do
  use ExUnit.Case
  import Sobelow, only: [is_vuln?: 1]
  alias Sobelow.RCE.CodeModule

  @evil_funcs [:eval_string, :eval_file, :eval_quoted]

  test "Code Execution in Code functions" do
    Enum.each @evil_funcs, fn evil_func ->
      func = """
      def func(eval_input) do
        Code.#{evil_func}(eval_input)
      end
      """

      {_, ast} = Code.string_to_quoted(func)

      assert CodeModule.parse_def(ast, evil_func) |> is_vuln?
    end
  end

  test "Safe Code functions" do
    Enum.each @evil_funcs, fn evil_func ->
      func = """
      def func() do
        Code.#{evil_func}("IO.inspect(1)")
      end
      """

      {_, ast} = Code.string_to_quoted(func)

      refute CodeModule.parse_def(ast, evil_func) |> is_vuln?
    end
  end
end