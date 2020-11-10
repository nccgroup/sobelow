defmodule Sobelow.Config do
  alias Sobelow.Parse
  alias Sobelow.Config.CSRF
  alias Sobelow.Config.CSRFRoute
  alias Sobelow.Config.CSP
  alias Sobelow.Config.Headers
  alias Sobelow.Config.CSWH

  @submodules [
    Sobelow.Config.CSRF,
    Sobelow.Config.CSRFRoute,
    Sobelow.Config.Headers,
    Sobelow.Config.CSP,
    Sobelow.Config.Secrets,
    Sobelow.Config.HTTPS,
    Sobelow.Config.HSTS,
    Sobelow.Config.CSWH
  ]

  use Sobelow.FindingType
  @skip_files ["dev.exs", "test.exs", "dev.secret.exs", "test.secret.exs"]

  def fetch(root, router, endpoints) do
    allowed = @submodules -- Sobelow.get_ignored()
    ignored_files = Sobelow.get_env(:ignored_files)

    dir_path = root <> "config/"

    Enum.each(allowed, fn mod ->
      cond do
        mod in [CSRF, CSRFRoute, Headers, CSP] ->
          Enum.each(router, fn path ->
            apply(mod, :run, [relative_path(path, root)])
          end)

        mod in [CSWH] ->
          Enum.each(endpoints, fn path ->
            apply(mod, :run, [relative_path(path, root)])
          end)

        File.dir?(dir_path) ->
          configs =
            File.ls!(dir_path)
            |> Enum.filter(&want_to_scan?(dir_path <> &1, ignored_files))

          apply(mod, :run, [dir_path, configs])

        true ->
          nil
      end
    end)
  end

  defp want_to_scan?(conf, ignored_files) do
    if Path.extname(conf) === ".exs" && !Enum.member?(@skip_files, Path.basename(conf)) &&
         !Enum.member?(ignored_files, Path.expand(conf)),
       do: conf
  end

  defp relative_path(path, root) do
    path = Path.relative_to(path, Path.expand(root))

    case Path.type(path) do
      :absolute -> path
      _ -> root <> path
    end
  end

  def get_configs_by_file(secret, file) do
    if File.exists?(file) do
      get_configs(secret, file)
    else
      []
    end
  end

  # Config utils

  def get_pipelines(filepath) do
    ast = Parse.ast(filepath)
    {_, acc} = Macro.prewalk(ast, [], &Parse.get_funs_of_type(&1, &2, :pipeline))
    acc
  end

  def get_plug_list(block) do
    case block do
      {:__block__, _, list} -> list
      {_, _, _} = list -> [list]
      _ -> []
    end
    |> Enum.reject(fn {type, _, _} -> type !== :plug end)
  end

  def is_vuln_pipeline?({:pipeline, _, [_name, [do: block]]}, :csrf) do
    plugs = get_plug_list(block)
    has_csrf? = Enum.any?(plugs, &is_plug?(&1, :protect_from_forgery))
    has_session? = Enum.any?(plugs, &is_plug?(&1, :fetch_session))

    has_session? and not has_csrf?
  end

  def is_vuln_pipeline?({:pipeline, _, [_name, [do: block]]}, :headers) do
    plugs = get_plug_list(block)
    has_headers? = Enum.any?(plugs, &is_plug?(&1, :put_secure_browser_headers))
    accepts = Enum.find_value(plugs, &get_plug_accepts/1)

    !has_headers? && is_list(accepts) && Enum.member?(accepts, "html")
  end

  def get_plug_accepts({:plug, _, [:accepts, {:sigil_w, _, opts}]}), do: parse_accepts(opts)
  def get_plug_accepts({:plug, _, [:accepts, accepts]}), do: accepts
  def get_plug_accepts(_), do: []

  def parse_accepts([{:<<>>, _, [accepts | _]}, []]), do: String.split(accepts, " ")

  def is_plug?({:plug, _, [type]}, type), do: true
  def is_plug?({:plug, _, [type, _]}, type), do: true
  def is_plug?(_, _), do: false

  def get_fuzzy_configs(key, filepath) do
    ast = Parse.ast(filepath)
    {_, acc} = Macro.prewalk(ast, [], &extract_fuzzy_configs(&1, &2, key))
    acc
  end

  def get_configs(key, filepath) do
    ast = Parse.ast(filepath)
    {_, acc} = Macro.prewalk(ast, [], &extract_configs(&1, &2, key))
    acc
  end

  defp extract_fuzzy_configs({:config, _, opts} = ast, acc, key) when is_list(opts) do
    opt = List.last(opts)
    vals = if Keyword.keyword?(opt), do: fuzzy_keyword_get(opt, key), else: nil

    if is_nil(vals) do
      {ast, acc}
    else
      {ast, [{ast, vals} | acc]}
    end
  end

  defp extract_fuzzy_configs(ast, acc, _key) do
    {ast, acc}
  end

  defp extract_configs({:config, _, opts} = ast, acc, key) when is_list(opts) do
    opt = List.last(opts)
    val = if Keyword.keyword?(opt), do: Keyword.get(opt, key), else: nil

    if is_nil(val) do
      {ast, acc}
    else
      {ast, [{ast, key, val} | acc]}
    end
  end

  defp extract_configs(ast, acc, _key) do
    {ast, acc}
  end

  defp fuzzy_keyword_get(opt, key) do
    keys = Keyword.keys(opt)

    Enum.map(keys, fn k ->
      if is_atom(k) && k != :secret_key_base do
        s = Atom.to_string(k) |> String.downcase()
        if String.contains?(s, key), do: {k, Keyword.get(opt, k)}
      end
    end)
    |> Enum.reject(&is_nil/1)
  end

  def get_version(filepath) do
    ast = Parse.ast(filepath)
    {_, acc} = Macro.prewalk(ast, [], &get_version(&1, &2))
    acc
  end

  def get_version({:@, _, nil} = ast, acc), do: {ast, acc}
  def get_version({:@, _, [{:version, _, [vsn]}]}, _acc) when is_binary(vsn), do: {vsn, vsn}
  def get_version(ast, acc), do: {ast, acc}
end
