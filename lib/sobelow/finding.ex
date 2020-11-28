defmodule Sobelow.Finding do
  defstruct [
    :type,
    :confidence,
    :filename,
    :vuln_line_no,
    :vuln_col_no,
    :vuln_variable,
    :vuln_source,
    :fun_name,
    :fun_line_no,
    :fun_source,
    :fingerprint
  ]

  alias Sobelow.Utils

  def init(type, filename, confidence \\ nil) do
    %Sobelow.Finding{
      type: type,
      filename: filename,
      confidence: confidence
    }
  end

  def multi_from_def(%Sobelow.Finding{} = finding, fun, {vulns, params, {fun_name, fun_line_no}}) do
    finding = %{finding | fun_name: fun_name, fun_line_no: fun_line_no, fun_source: fun}

    Enum.map(vulns, fn {vuln, var} ->
      %{
        finding
        | vuln_variable: var,
          vuln_source: vuln,
          vuln_line_no: Sobelow.Parse.get_fun_line(vuln),
          vuln_col_no: Sobelow.Parse.get_fun_column(vuln),
          confidence: Sobelow.Print.get_sev(params, var, finding.confidence)
      }
      |> normalize()
    end)
  end

  def fetch_fingerprint(%Sobelow.Finding{} = finding) do
    %{finding | fingerprint: fingerprint(finding)}
  end

  def fingerprint(%Sobelow.Finding{} = finding) do
    filename =
      Utils.get_root()
      |> Utils.normalize_path()
      |> (&String.replace_prefix(finding.filename, &1, "")).()
      |> Utils.normalize_path()

    [finding.type, finding.vuln_source, filename, finding.vuln_line_no]
    |> :erlang.term_to_binary()
    |> :erlang.md5()
    |> Base.encode16()
  end

  defp normalize(%Sobelow.Finding{vuln_variable: vars} = finding) when is_list(vars) do
    var = if length(vars) > 1, do: Enum.join(vars, " and "), else: hd(vars)

    %{finding | vuln_variable: var} |> normalize()
  end

  defp normalize(%Sobelow.Finding{fun_source: fun} = finding) when is_list(fun) do
    %{finding | fun_source: List.first(fun)} |> normalize()
  end

  defp normalize(finding), do: finding

  defmacro __using__(_) do
    quote do
      alias Sobelow.Finding
      alias Sobelow.Parse
      alias Sobelow.Print
      alias Sobelow.Utils

      def details() do
        @moduledoc
      end

      def id() do
        "SBLW" <> String.pad_leading("#{@uid}", 3, "0")
      end

      def rule() do
        [name, description] = String.split(@finding_type, ":", parts: 2)

        description = String.trim(description)

        rule_details =
          details()
          |> String.split("\n\n")
          |> Enum.map(fn para -> String.replace(para, "\n", " ") end)
          |> Enum.join("\n\n")

        %{
          id: id(),
          name: name,
          shortDescription: %{text: description},
          fullDescription: %{text: description},
          help: %{
            text: rule_details,
            markdown: rule_details
          }
        }
      end

      defoverridable details: 0
    end
  end
end

defmodule Sobelow.FindingType do
  defmacro __using__(_) do
    quote do
      def finding_modules() do
        @submodules
      end

      def details() do
        Enum.map(@submodules, fn sub ->
          apply(sub, :details, [])
        end)
      end

      def rules() do
        Enum.map(@submodules, fn sub ->
          apply(sub, :rule, [])
        end)
      end

      defoverridable details: 0
    end
  end
end
