defmodule SobelowTest.SonarQubeTest do
  use ExUnit.Case
  alias Sobelow.{FindingLog, Fingerprint}

  # log_json_finding(line_no, filename, fun_name, var, severity, type)
  test "Log Sonarqube finding with function as function name" do
    output = """
    {
      "issues": [
        {
          "engineId": "sobelow1.0.0",
          "primaryLocation": {
            "filePath": "./file.ex",
            "message": "N/A var",
            "textRange": {
              "startLine": 1
            }
          },
          "ruleId": "N/A",
          "severity": "CRITICAL",
          "type": "VULNERABILITY"
        }
      ]
    }
    """

    FindingLog.start_link()
    Fingerprint.start_link()

    finding = %Sobelow.Finding{
      confidence: :high,
      filename: "file.ex",
      type: "N/A",
      vuln_line_no: 1,
      vuln_variable: "var"
    }

    Sobelow.log_finding(finding.type, finding)

    assert FindingLog.formatted_output("sonarqube", "1.0.0") <> "\n" == output
  end
end
