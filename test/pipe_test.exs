defmodule SobelowTest.PipeTest do
  use ExUnit.Case
  import Sobelow, only: [vuln?: 1]
  alias Sobelow.DOS.StringToAtom
  alias Sobelow.Misc.BinToTerm

  test "Simple Pipe" do
    func = """
    def show(conn, %{"page" => page}) do
      template = page |> String.to_atom()
      render conn, template
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    assert StringToAtom.parse_def(ast) |> vuln?
  end

  test "Nested Pipe" do
    func = """
    def show(conn, %{"page" => page}) do
      template = page |> Page.get_template() |> String.to_atom()
      render conn, template
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    assert StringToAtom.parse_def(ast) |> vuln?
  end

  test "Piped String is not vulnerable" do
    func = """
    def show(conn, %{"page" => page}) do
      template = "page" |> String.to_atom()
      render conn, template, var: page
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    refute StringToAtom.parse_def(ast) |> vuln?
  end

  test "Pipe in function" do
    func = """
    def show(conn, %{"page" => page}) do
      render conn, page |> String.to_atom()
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    assert StringToAtom.parse_def(ast) |> vuln?
  end

  test "Pipe in piped function" do
    func = """
    def show(conn, %{"page" => page}) do
      conn
      |> render(page |> String.to_atom)
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    assert StringToAtom.parse_def(ast) |> vuln?
  end

  test "Unpiped in piped function" do
    func = """
    def show(conn, %{"page" => page}) do
      conn
      |> render(String.to_atom(page))
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    assert StringToAtom.parse_def(ast) |> vuln?
  end

  test "Unpiped anonymous function in piped function" do
    func = """
    def show(conn, %{"pages" => pages}) do
      pages
      |> Enum.each(&String.to_atom/1)
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    assert StringToAtom.parse_def(ast) |> vuln?
  end

  test "Pipe to erlang module" do
    func = """
    def show(conn, %{"data" => data}) do
      data |> :erlang.binary_to_term()
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    assert BinToTerm.parse_def(ast) |> vuln?
  end

  test "Unpiped erlang module in piped function" do
    func = """
    def show(conn, %{"page" => page}) do
      conn
      |> func(:erlang.binary_to_term(page))
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    assert BinToTerm.parse_def(ast) |> vuln?
  end

  test "Safe unpiped in piped function" do
    func = """
    def show(conn, %{"page" => page}) do
      conn
      |> render(String.to_atom("index"))
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    refute StringToAtom.parse_def(ast) |> vuln?
  end
end
