defmodule SobelowTest.RCE.EExTest do
  use ExUnit.Case
  import Sobelow, only: [is_vuln?: 1]
  alias Sobelow.RCE.EEx

  @evil_funcs [:eval_string, :eval_file]

  test "Code Execution in EEx functions" do
    Enum.each @evil_funcs, fn evil_func ->
      func = """
      def func(eval_input) do
        EEx.#{evil_func}(eval_input)
      end
      """

      {_, ast} = Code.string_to_quoted(func)

      assert EEx.parse_def(ast, evil_func) |> is_vuln?
    end
  end

  test "Safe EEx functions" do
    Enum.each @evil_funcs, fn evil_func ->
      func = """
      def func() do
        EEx.#{evil_func}("IO.inspect(1)")
      end
      """

      {_, ast} = Code.string_to_quoted(func)

      refute EEx.parse_def(ast, evil_func) |> is_vuln?
    end
  end
end