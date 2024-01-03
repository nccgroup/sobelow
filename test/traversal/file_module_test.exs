defmodule SobelowTest.Traversal.FileModuleTest do
  use ExUnit.Case
  import Sobelow, only: [is_vuln?: 1]
  alias Sobelow.Traversal.FileModule

  @evil_funcs [:read, :read!, :write, :write!, :rm, :rm!, :rm_rf, :stream, :stream!]

  @double_evil_funcs [:cp, :cp!, :cp_r, :cp_r!, :ln, :ln!, :ln_s, :ln_s!]

  test "Traversal in File functions first parameter" do
    Enum.each(@evil_funcs, fn evil_func ->
      func = """
      def func(file_name) do
        File.#{evil_func}(file_name)
      end
      """

      {_, ast} = Code.string_to_quoted(func)

      assert FileModule.parse_def(ast, evil_func) |> is_vuln?
    end)
  end

  test "Traversal in File functions second parameter" do
    Enum.each(@double_evil_funcs, fn evil_func ->
      func = """
      def func(file_name) do
        File.#{evil_func}("file.txt", file_name)
      end
      """

      {_, ast} = Code.string_to_quoted(func)

      assert FileModule.parse_second_def(ast, evil_func) |> is_vuln?
    end)
  end

  test "Safe File functions" do
    Enum.each(@evil_funcs, fn evil_func ->
      func = """
      def func() do
        File.#{evil_func}("file.txt")
      end
      """

      {_, ast} = Code.string_to_quoted(func)

      refute FileModule.parse_def(ast, evil_func) |> is_vuln?
    end)
  end
end
