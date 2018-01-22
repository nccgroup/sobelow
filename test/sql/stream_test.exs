defmodule SobelowTest.SQL.StreamTest do
  use ExUnit.Case
  import Sobelow, only: [is_vuln?: 1]
  alias Sobelow.SQL.Stream

  test "SQL injection in `SQL.stream`" do
    func = """
    def query(%{"sql" => sql}) do
      SQL.stream(Repo, sql, [])
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    assert Stream.parse_sql_def(ast) |> is_vuln?
  end

  test "Safe `SQL.stream`" do
    func = """
    def query(%{"sql" => sql}) do
      SQL.stream(Repo, "SELECT * FROM users", [])
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    refute Stream.parse_sql_def(ast) |> is_vuln?
  end
end
