defmodule SobelowTest.LogTest do
  use ExUnit.Case
  alias Sobelow.{Utils, FindingLog}

  # log_json_finding(line_no, filename, fun_name, var, severity, type)
  test "Log JSON finding with function as function name" do
    output = """
    {
       "findings": {
          "high_confidence": [
             {
                "file": "file.ex",
                "function": "function(:details):1",
                "type": "N/A",
                "variable": "var"
             }
          ],
          "low_confidence": [

          ],
          "medium_confidence": [

          ]
       },
       "sobelow_version": "1.0.0",
       "total_findings": 1
    }
    """

    FindingLog.start_link()
    Utils.log_json_finding(1, "file.ex", {:function, [], [:details]}, "var", :high, "N/A")

    assert FindingLog.json("1.0.0") <> "\n" == output
  end
end
