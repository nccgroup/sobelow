defmodule SobelowTest.SarifTest do
  use ExUnit.Case

  alias Sobelow.RCE.CodeModule

  @metafile %{filename: "test.ex", controller?: true}

  setup do
    Application.put_env(:sobelow, :format, "sarif")
    Sobelow.Fingerprint.start_link()
    Sobelow.FindingLog.start_link()

    :ok
  end

  test "Unique rule ids" do
    ids = Sobelow.rules() |> Enum.map(& &1.id)

    assert Enum.uniq(ids) |> length() == length(ids)
  end

  test "All finding modules have an id" do
    ids = Sobelow.finding_modules() |> Enum.map(&apply(&1, :id, []))

    assert Enum.uniq(ids) |> length() == length(ids)
  end

  test "All finding modules have docs" do
    assert Sobelow.finding_modules() |> Enum.map(&apply(&1, :details, [])) |> length() ==
             Sobelow.finding_modules() |> length()
  end

  test "All required fields available" do
    func = """
    def call(conn, _opts) do
      Code.eval_string(conn.body_params["code"])
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    run_test = fn ->
      CodeModule.run(ast, @metafile)
    end

    run_test.()

    output = Jason.decode!(Sobelow.FindingLog.sarif("1"))
    run = List.first(output["runs"])
    results = run["results"]

    assert output["$schema"] ==
             "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

    assert output["version"] == "2.1.0"
    assert is_list(output["runs"])
    assert run["tool"]["driver"]["name"] == "Sobelow"
    assert is_list(run["results"])
    assert Enum.all?(results, &is_binary(&1["ruleId"]))
    assert Enum.all?(results, &is_binary(&1["message"]["text"]))
    assert Enum.all?(results, &is_list(&1["locations"]))

    assert Enum.all?(results, fn result ->
             Enum.all?(result["locations"], fn location ->
               region = location["physicalLocation"]["region"]

               is_binary(location["physicalLocation"]["artifactLocation"]["uri"]) &&
                 is_number(region["startLine"]) && is_number(region["startColumn"]) &&
                 is_number(region["endLine"]) && is_number(region["endColumn"])
             end)
           end)

    assert Enum.all?(results, &is_binary(&1["partialFingerprints"]["primaryLocationLineHash"]))
  end
end
