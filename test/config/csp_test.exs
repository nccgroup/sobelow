defmodule SobelowTest.Config.CSPTest do
  use ExUnit.Case
  alias Sobelow.{Config, Parse}
  alias Sobelow.Config.CSP

  test "Missing CSP" do
    router = "./test/fixtures/csp/bad_router.ex"

    meta_file =
      Parse.ast(router)
      |> Parse.get_meta_funs()

    assert Config.get_pipelines(router)
           |> Enum.map(&CSP.check_vuln_pipeline(&1, meta_file))
           |> Enum.any?(&vuln?/1)
  end

  test "Inline CSP" do
    router = "./test/fixtures/csp/good_router.ex"

    meta_file =
      Parse.ast(router)
      |> Parse.get_meta_funs()

    refute Config.get_pipelines(router)
           |> Enum.map(&CSP.check_vuln_pipeline(&1, meta_file))
           |> Enum.any?(&vuln?/1)
  end

  test "Module Attribute CSP" do
    router = "./test/fixtures/csp/good_router_attr.ex"

    meta_file =
      Parse.ast(router)
      |> Parse.get_meta_funs()

    refute Config.get_pipelines(router)
           |> Enum.map(&CSP.check_vuln_pipeline(&1, meta_file))
           |> Enum.any?(&vuln?/1)
  end

  test "Module Attribute Missing CSP" do
    router = "./test/fixtures/csp/bad_router_attr.ex"

    meta_file =
      Parse.ast(router)
      |> Parse.get_meta_funs()

    assert Config.get_pipelines(router)
           |> Enum.map(&CSP.check_vuln_pipeline(&1, meta_file))
           |> Enum.any?(&vuln?/1)
  end

  defp vuln?({true, _, _, _}), do: true
  defp vuln?(_), do: false
end
