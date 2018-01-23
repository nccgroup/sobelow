defmodule SobelowTest.LogTest do
  use ExUnit.Case
  alias Sobelow.{Utils, FindingLog}

  # log_json_finding(line_no, filename, fun_name, var, severity, type)
  test "Log JSON finding with function as function name" do
    output = """
    {
      "sobelow_version": "1.0.0",
      "total_findings": "1",
      "findings": {
        "high_confidence": [
          {
            "type": "N/A",
            "file": "file.ex",
            "function": "function(:details):1",
            "variable": "var"
          }
        ],
        "medium_confidence": [
        ],
        "low_confidence": [
        ]
      }
    }
    """

    FindingLog.start_link()
    Utils.log_json_finding(1, "file.ex", {:function, [], [:details]}, "var", :high, "N/A")

    assert FindingLog.json("1.0.0") == output
  end
end
