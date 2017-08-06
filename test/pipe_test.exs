defmodule SobelowTest.PipeTest do
  use ExUnit.Case
  import Sobelow, only: [is_vuln?: 1]
  alias Sobelow.DOS.StringToAtom

  test "Simple Pipe" do
    func = """
    def show(conn, %{"page" => page}) do
      template = page |> String.to_atom()
      render conn, template
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    assert StringToAtom.parse_def(ast) |> is_vuln?
  end

  test "Nested Pipe" do
    func = """
    def show(conn, %{"page" => page}) do
      template = page |> Page.get_template() |> String.to_atom()
      render conn, template
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    assert StringToAtom.parse_def(ast) |> is_vuln?
  end

  test "Piped String is not vulnerable" do
    func = """
    def show(conn, %{"page" => page}) do
      template = "page" |> String.to_atom()
      render conn, template, var: page
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    refute StringToAtom.parse_def(ast) |> is_vuln?
  end

  test "Pipe in function" do
    func = """
    def show(conn, %{"page" => page}) do
      render conn, page |> String.to_atom()
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    assert StringToAtom.parse_def(ast) |> is_vuln?
  end

  test "Pipe in piped function" do
    func = """
    def show(conn, %{"page" => page}) do
      conn
      |> render(page |> String.to_atom)
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    assert StringToAtom.parse_def(ast) |> is_vuln?
  end

#  test "Command Injection in indirect `:os.cmd`" do
#    func = """
#    def show(conn, %{"page" => page}) do
#      conn
#      |> render(page |> String.to_atom)
#    end
#    """
#
#    {_, ast} = Code.string_to_quoted(func)
#
#    assert OS.parse_def(ast) |> is_vuln?
#  end

end