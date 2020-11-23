defmodule Sobelow.Config.CSRFRoute do
  @moduledoc """
  # Cross-Site Request Forgery

  In a Cross-Site Request Forgery (CSRF) attack, an untrusted
  application can cause a user's browser to submit requests or perform
  actions on the user's behalf.

  Read more about CSRF here:
  https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)

  This type of CSRF is flagged by `sobelow` when state-changing
  routes share an action with GET-based routes. For example:

      get "/users", UserController, :new
      post "/users", UserController, :new

  In this instance, it may be possible to trigger the POST
  functionality with a GET request and query parameters.

  CSRF checks can be ignored with the following command:

      $ mix sobelow -i Config.CSRFRoute
  """

  alias Sobelow.Parse

  @uid 4
  @finding_type "Config.CSRFRoute: CSRF via Action Reuse"

  use Sobelow.Finding

  @state_changing_methods [:post, :put, :patch, :delete]

  def run(router) do
    finding = Finding.init(@finding_type, Utils.normalize_path(router))

    router
    |> Parse.ast()
    |> Parse.get_top_level_funs_of_type(:scope)
    |> combine_scopes()
    |> Stream.flat_map(&route_findings(&1, finding))
    # Sort for deterministic txt-format output
    |> Enum.sort()
    |> Enum.each(&add_finding/1)
  end

  def route_findings(scope, finding) do
    scope
    |> Parse.get_funs_of_type([:get | @state_changing_methods])
    |> Enum.reduce(%{}, &transform_routes/2)
    |> Stream.filter(&get_and_state_changing?/1)
    |> Stream.flat_map(&put_finding_details(&1, finding))
  end

  defp put_finding_details({_, meta}, %Finding{fun_source: nil} = finding) do
    src = Enum.map(meta, fn {_, v} -> v end)

    Enum.reduce(
      meta,
      [],
      &put_finding_details(&1, &2, %{finding | fun_source: {:__block__, [], src}})
    )
  end

  defp put_finding_details({:get, fun}, acc, finding) do
    finding = %{
      finding
      | vuln_source: fun,
        vuln_line_no: Parse.get_fun_line(fun),
        vuln_col_no: Parse.get_fun_column(fun),
        fun_name: get_action(fun),
        confidence: :high
    }

    [finding | acc]
  end

  defp put_finding_details(_, acc, _), do: acc

  defp add_finding(%Finding{} = finding) do
    finding = Finding.fetch_fingerprint(finding)
    file_header = "File: #{finding.filename}"
    action_header = "Action: #{finding.fun_name}"
    line_header = "Line: #{finding.vuln_line_no}"

    case Sobelow.format() do
      "json" ->
        json_finding = [
          type: finding.type,
          file: finding.filename,
          route: finding.fun_name,
          line: finding.vuln_line_no
        ]

        Sobelow.log_finding(json_finding, finding)

      "txt" ->
        Sobelow.log_finding(finding)

        Print.print_custom_finding_metadata(
          finding,
          [file_header, action_header, line_header]
        )

      "compact" ->
        Print.log_compact_finding(finding)

      _ ->
        Sobelow.log_finding(finding)
    end
  end

  def combine_scopes(scopes) do
    scopes
    |> Stream.map(&get_alias_and_list/1)
    |> Enum.reduce(%{}, &transform_scopes/2)
    |> Map.values()
  end

  defp get_alias_and_list({:scope, _, [_path, alias, _opts, list]}) do
    {get_alias(alias), list[:do]}
  end

  defp get_alias_and_list({:scope, _, [_path, opts, list]}), do: {get_alias(opts), list[:do]}
  defp get_alias_and_list({:scope, _, [opts, list]}), do: {get_alias(opts), list[:do]}

  defp get_alias({fun, _, opts}), do: {fun, [], opts}

  defp get_alias(opts) when is_list(opts) do
    opts[:alias]
  end

  defp get_alias(_), do: nil

  defp get_and_state_changing?({_, meta}) do
    has_method?(meta, :get) && Enum.any?(@state_changing_methods, &has_method?(meta, &1))
  end

  defp has_method?(meta, action) do
    Enum.any?(meta, fn {method, _} -> method == action end)
  end

  defp transform_routes({method, _, opts} = fun, acc) do
    value = {method, fun}
    Map.update(acc, get_ca(opts), [value], &[value | &1])
  end

  defp transform_scopes({scope, routes}, acc) do
    Map.update(acc, scope, [routes], &[routes | &1])
  end

  defp get_action({_, _, opts}) when is_list(opts), do: get_action(opts)
  defp get_action([_, _, action | _]), do: action

  defp get_ca([_path, controller, action | _]) do
    [normalize_controller(controller), action]
  end

  defp normalize_controller({:__aliases__, _, controller}), do: controller
  defp normalize_controller({fun, _, opts}), do: {fun, [], opts}
end
