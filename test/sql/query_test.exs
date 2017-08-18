defmodule SobelowTest.SQL.QueryTest do
  use ExUnit.Case
  import Sobelow, only: [is_vuln?: 1]
  alias Sobelow.SQL.Query

  test "SQL injection in `SQL`" do
    func = """
    def query(%{"sql" => sql}) do
      SQL.query(Repo, sql, [])
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    assert Query.parse_sql_def(ast) |> is_vuln?
  end

  test "Safe `SQL`" do
    func = """
    def query(%{"sql" => sql}) do
      SQL.query(Repo, "SELECT * FROM users", [])
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    refute Query.parse_sql_def(ast) |> is_vuln?
  end

  test "SQL injection in `Repo`" do
    func = """
    def query(%{"sql" => sql}) do
      Repo.query(sql)
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    assert Query.parse_repo_query_def(ast) |> is_vuln?
  end

  test "safe `Repo`" do
    func = """
    def query(%{"sql" => sql}) do
      Repo.query("SELECT * FROM users")
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    refute Query.parse_repo_query_def(ast) |> is_vuln?
  end
end