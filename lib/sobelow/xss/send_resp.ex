defmodule Sobelow.XSS.SendResp do
  @uid 31
  @finding_type "XSS.SendResp: XSS in `send_resp`"

  use Sobelow.Finding

  def run(fun, meta_file) do
    Finding.init(@finding_type, meta_file.filename, nil)
    |> Finding.multi_from_def(fun, parse_def(fun))
    |> Stream.map(&set_confidence/1)
    |> Stream.reject(&nil_confidence?/1)
    |> Enum.each(&Print.add_finding(&1))
  end

  def parse_def(fun) do
    Parse.get_fun_vars_and_meta(fun, 2, :send_resp, :Conn)
  end

  def details() do
    Sobelow.XSS.details()
  end

  @doc false
  def get_content_type({:put_resp_content_type, _, opts}), do: hd(opts)
  def get_content_type({{_, _, [_, :put_resp_content_type]}, _, opts}), do: hd(opts)

  @doc false
  def set_confidence(%Finding{} = finding) do
    content_types =
      finding.fun_source
      |> Parse.get_funs_of_type(:put_resp_content_type)
      |> Kernel.++(
        Parse.get_aliased_funs_of_type(finding.fun_source, :put_resp_content_type, :Conn)
      )
      |> Enum.map(&get_content_type/1)

    %{finding | confidence: get_confidence(finding, content_types)}
  end

  defp get_confidence(finding, content_types) do
    cond do
      length(content_types) == 0 ->
        finding.confidence

      Enum.any?(content_types, &(!is_binary(&1))) ->
        :low

      Enum.all?(content_types, &contains_html?/1) ->
        finding.confidence

      Enum.any?(content_types, &contains_html?/1) ->
        :low

      true ->
        nil
    end
  end

  defp contains_html?(content_type) do
    content_type
    |> String.downcase()
    |> String.contains?("html")
  end

  @doc false
  def nil_confidence?(%Finding{confidence: nil}), do: true
  def nil_confidence?(_), do: false
end
