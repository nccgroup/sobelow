defmodule Sobelow.Finding do
  defstruct [
    :type,
    :confidence,
    :filename,
    :vuln_line_no,
    :vuln_variable,
    :vuln_source,
    :fun_name,
    :fun_line_no,
    :fun_source
  ]

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
          confidence: Sobelow.Print.get_sev(params, var, finding.confidence)
      }
      |> normalize()
    end)
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
        IO.ANSI.Docs.print(@moduledoc)
      end

      defoverridable details: 0
    end
  end
end

defmodule Sobelow.FindingType do
  defmacro __using__(_) do
    quote do
      def details() do
        Enum.each(@submodules, fn sub ->
          apply(sub, :details, [])
        end)
      end

      defoverridable details: 0
    end
  end
end
