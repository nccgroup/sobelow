defmodule SobelowTest.SQL.QueryTest do
  use ExUnit.Case
  import Sobelow, only: [is_vuln?: 1]
  alias Sobelow.SQL.Query

  @query_funcs [:query, :query!]

  test "SQL injection in `SQL`" do
    Enum.each(@query_funcs, fn query_func ->
      func = """
      def query(%{"sql" => sql}) do
        SQL.#{query_func}(Repo, sql, [])
      end
      """

      {_, ast} = Code.string_to_quoted(func)

      assert Query.parse_sql_def(ast, query_func) |> is_vuln?
    end)
  end

  test "Safe `SQL`" do
    Enum.each(@query_funcs, fn query_func ->
      func = """
      def query(%{"sql" => sql}) do
        SQL.#{query_func}(Repo, "SELECT * FROM users", [])
      end
      """

      {_, ast} = Code.string_to_quoted(func)

      refute Query.parse_sql_def(ast, query_func) |> is_vuln?
    end)
  end

  test "SQL injection in `Repo`" do
    Enum.each(@query_funcs, fn query_func ->
      func = """
      def query(%{"sql" => sql}) do
        Repo.#{query_func}(sql)
      end
      """

      {_, ast} = Code.string_to_quoted(func)

      assert Query.parse_repo_query_def(ast, query_func) |> is_vuln?
    end)
  end

  test "safe `Repo`" do
    Enum.each(@query_funcs, fn query_func ->
      func = """
      def query(%{"sql" => sql}) do
        Repo.#{query_func}("SELECT * FROM users")
      end
      """

      {_, ast} = Code.string_to_quoted(func)

      refute Query.parse_repo_query_def(ast, query_func) |> is_vuln?
    end)
  end
end
