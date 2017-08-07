defmodule SobelowTest.Misc.BinToTerm do
  use ExUnit.Case
  import Sobelow, only: [is_vuln?: 1]
  alias Sobelow.Misc.BinToTerm

  test "Unsafe `binary_to_term`" do
    func = """
    def index(conn, %{"test" => test}) do
      :erlang.binary_to_term(test)
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    assert BinToTerm.parse_def(ast) |> is_vuln?
  end

  test "Unsafe indirect `binary_to_term`" do
    func = """
    def index(conn, params) do
      :erlang.binary_to_term(params["test"])
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    assert BinToTerm.parse_def(ast) |> is_vuln?
  end

  test "safe `binary_to_term`" do
    func = """
    def index(conn, %{"test" => test}) do
      :erlang.binary_to_term(<<131, 97, 1>>)
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    refute BinToTerm.parse_def(ast) |> is_vuln?
  end

  test "Piped `binary_to_term`" do
    func = """
    def index(conn, %{"test" => test}) do
      test |> :erlang.binary_to_term()
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    assert BinToTerm.parse_def(ast) |> is_vuln?
  end

  test "Pipe to Piped `binary_to_term`" do
    func = """
    def index(conn, %{"test" => test}) do
      conn |> func(test |> :erlang.binary_to_term())
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    assert BinToTerm.parse_def(ast) |> is_vuln?
  end
end