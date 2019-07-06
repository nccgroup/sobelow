defmodule SobelowTest.Config.CSRFRouteTest do
  use ExUnit.Case
  alias Sobelow.Config.CSRFRoute
  alias Sobelow.{Finding,Parse}

  test "flags vulnerable routes in standard case" do
    code = """
    scope "/", MyApp do
      get "/", MyController, :action
      post "/", MyController, :action
    end
    """

    {_, ast} = Code.string_to_quoted(code)

    vulns =
      ast
      |> Parse.get_top_level_funs_of_type(:scope)
      |> CSRFRoute.combine_scopes()
      |> Enum.flat_map(&CSRFRoute.route_findings(&1, %Finding{}))

    assert length(vulns) == 1
  end

  test "flags vulnerable routes across scopes" do
    code = """
    scope "/", MyApp do
      get "/", MyController, :action
    end

    scope "/test", MyApp do
      post "/ing", MyController, :action
    end
    """

    {_, ast} = Code.string_to_quoted(code)

    vulns =
      ast
      |> Parse.get_top_level_funs_of_type(:scope)
      |> CSRFRoute.combine_scopes()
      |> Enum.flat_map(&CSRFRoute.route_findings(&1, %Finding{}))

    assert length(vulns) == 1
  end

  test "does not flag safe routes across scopes" do
    code = """
    scope "/", MyApp do
      get "/", MyController, :action
    end

    scope "/test", MyAppTwo do
      post "/ing", MyController, :action
    end
    """

    {_, ast} = Code.string_to_quoted(code)

    vulns =
      ast
      |> Parse.get_top_level_funs_of_type(:scope)
      |> CSRFRoute.combine_scopes()
      |> Enum.flat_map(&CSRFRoute.route_findings(&1, %Finding{}))

    assert length(vulns) == 0
  end

  test "flags vulnerable routes in nested scopes" do
    code = """
    scope "/", MyApp do
      get "/", MyController, :action

      scope "/test" do
        post "/ing", MyController, :action
      end
    end
    """

    {_, ast} = Code.string_to_quoted(code)

    vulns =
      ast
      |> Parse.get_top_level_funs_of_type(:scope)
      |> CSRFRoute.combine_scopes()
      |> Enum.flat_map(&CSRFRoute.route_findings(&1, %Finding{}))

    assert length(vulns) == 1
  end
end
