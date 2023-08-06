defmodule SobelowTest.LogTest do
  use ExUnit.Case
  alias Sobelow.{FindingLog, Fingerprint}

  # log_json_finding(line_no, filename, fun_name, var, severity, type)
  test "Log JSON finding with function as function name" do
    output =
      Jason.decode!("""
      {
        "findings": {
          "high_confidence": [
            {
              "file": "file.ex",
              "line": 1,
              "type": "N/A",
              "variable": "var"
            }
          ],
          "low_confidence": [],
          "medium_confidence": []
        },
        "sobelow_version": "1.0.0",
        "total_findings": 1
      }
      """)

    FindingLog.start_link()
    Fingerprint.start_link()

    finding = [
      type: "N/A",
      file: "file.ex",
      line: 1,
      variable: "var"
    ]

    Sobelow.log_finding(finding, %Sobelow.Finding{confidence: :high})

    assert Jason.decode!(FindingLog.json("1.0.0")) == output
  end
end
