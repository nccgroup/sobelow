defmodule SobelowTest.Config.CSPTest do
  use ExUnit.Case
  alias Sobelow.Utils
  alias Sobelow.Config.CSP

  test "Missing CSP" do
    router = "./test/fixtures/csp/bad_router.ex"

    meta_file =
      Utils.ast(router)
      |> Utils.get_meta_funs()

    assert Utils.get_pipelines(router)
           |> Enum.map(&CSP.check_vuln_pipeline(&1, meta_file))
           |> Enum.any?(&is_vuln?/1)
  end

  test "Inline CSP" do
    router = "./test/fixtures/csp/good_router.ex"

    meta_file =
      Utils.ast(router)
      |> Utils.get_meta_funs()

    refute Utils.get_pipelines(router)
           |> Enum.map(&CSP.check_vuln_pipeline(&1, meta_file))
           |> Enum.any?(&is_vuln?/1)
  end

  test "Module Attribute CSP" do
    router = "./test/fixtures/csp/good_router_attr.ex"

    meta_file =
      Utils.ast(router)
      |> Utils.get_meta_funs()

    refute Utils.get_pipelines(router)
           |> Enum.map(&CSP.check_vuln_pipeline(&1, meta_file))
           |> Enum.any?(&is_vuln?/1)
  end

  test "Module Attribute Missing CSP" do
    router = "./test/fixtures/csp/bad_router_attr.ex"

    meta_file =
      Utils.ast(router)
      |> Utils.get_meta_funs()

    assert Utils.get_pipelines(router)
           |> Enum.map(&CSP.check_vuln_pipeline(&1, meta_file))
           |> Enum.any?(&is_vuln?/1)
  end

  defp is_vuln?({true, _, _}), do: true
  defp is_vuln?(_), do: false
end
