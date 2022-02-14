defmodule SobelowTest.SonarQubeTest do
  use ExUnit.Case
  alias Sobelow.{FindingLog, Fingerprint}

  # log_json_finding(line_no, filename, fun_name, var, severity, type)
  test "Log Sonarqube finding with function as function name" do
    output = """
    {
      "issues": [
        {
          "engineId": "sobelow-1.0.0",
          "primaryLocation": {
            "filePath": "file.ex",
            "message": "Traversal.FileModule: Description var \\n Help: # Path Traversal\\n\\nPath traversal vulnerabilities are a result of\\ninteracting with the filesystem using untrusted input.\\nThis class of vulnerability may result in file disclosure,\\ncode execution, denial of service, and other issues.\\n\\nRead more about Path Traversal here:\\nhttps://www.owasp.org/index.php/Path_Traversal\\n\\nPath Traversal checks can be ignored with the following command:\\n\\n    $ mix sobelow -i Traversal\\n\",
            "textRange": {
              "startLine": 1
            }
          },
          "ruleId": "SBLW019\",
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
      type: "Traversal.FileModule: Description",
      vuln_line_no: 1,
      vuln_variable: "var"
    }

    Sobelow.log_finding(finding.type, finding)

    assert FindingLog.formatted_output("sonarqube", "1.0.0") <> "\n" == output
  end
end
