defmodule SobelowTest.Config.CSWHTest do
  use ExUnit.Case
  alias Sobelow.Parse
  alias Sobelow.Config.CSWH

  test "checks normal endpoint" do
    endpoint = "./test/fixtures/cswh/good_endpoint.ex"

    is_vuln? =
      Parse.ast(endpoint)
      |> Parse.get_funs_of_type(:socket)
      |> Enum.any?(fn socket ->
        case CSWH.check_socket(socket) do
          {true, _} -> true
          _ -> false
        end
      end)

    refute is_vuln?
  end

  test "checks normal endpoint with configuration" do
    endpoint = "./test/fixtures/cswh/good_endpoint_2.ex"

    is_vuln? =
      Parse.ast(endpoint)
      |> Parse.get_funs_of_type(:socket)
      |> Enum.any?(fn socket ->
        case CSWH.check_socket(socket) do
          {true, _} -> true
          _ -> false
        end
      end)

    refute is_vuln?
  end

  test "checks no-check endpoint" do
    endpoint = "./test/fixtures/cswh/bad_endpoint.ex"

    is_vuln? =
      Parse.ast(endpoint)
      |> Parse.get_funs_of_type(:socket)
      |> Enum.any?(fn socket ->
        case CSWH.check_socket(socket) do
          {true, :high} -> true
          _ -> false
        end
      end)

    assert is_vuln?
  end

  test "checks loose check endpoint" do
    endpoint = "./test/fixtures/cswh/soso_endpoint.ex"

    is_vuln? =
      Parse.ast(endpoint)
      |> Parse.get_funs_of_type(:socket)
      |> Enum.any?(fn socket ->
        case CSWH.check_socket(socket) do
          {true, :low} -> true
          _ -> false
        end
      end)

    assert is_vuln?
  end
end
