defmodule Sobelow.Utilsx do
  require IEx

  # General Utils
  def ast(filepath) do
    {:ok, ast} = Code.string_to_quoted(File.read!(filepath))
    ast
  end

  defp get_funs_of_type({type, _, _} = ast, acc, type) do
    {ast, [ast|acc]}
  end
  defp get_funs_of_type(ast, acc, type), do: {ast, acc}

  # Setup Utils
  def get_app_name(filepath) do
    ast = ast(filepath)
    {_, project_block} = Macro.prewalk(ast, [], &extract_app_name/2)
    Atom.to_string(Keyword.get(project_block, :app))
  end

  defp extract_app_name({:def, _, [{:project, _, _}, [do: block]]} = ast, _) do
    {ast, block}
  end
  defp extract_app_name(ast, acc) do
    {ast, acc}
  end

  # Config utils

  def get_pipelines(filepath) do
    ast = ast(filepath)
    {_, acc} = Macro.prewalk(ast, [], &get_funs_of_type(&1, &2, :pipeline))
    acc
  end

  def is_vuln_pipeline({:pipeline, _, [name, [do: block]]}) do
    fun_list = case block do
      {:__block__, _, list} -> list
      {_, _, _} = list -> [list]
      _ -> []
    end

    plugs = fun_list
    |> Enum.reject(fn {type, _, _} -> type !== :plug end)

    accepts = Enum.find_value(plugs, &get_plug_accepts/1)
    csrf = Enum.find_value(plugs, &get_plug_csrf/1)

    if is_list(accepts) && Enum.member?(accepts, "html") && !csrf, do: true, else: false
  end

  def get_plug_accepts({:plug, _, [:accepts, accepts]}), do: accepts
  def get_plug_accepts(_), do: false
  def get_plug_csrf({:plug, _, [:protect_from_forgery]}), do: true
  def get_plug_csrf(_), do: false

  def get_configs(secret, filepath) do
    ast = ast(filepath)
    {ast, acc} = Macro.prewalk(ast, [], &extract_configs(&1, &2, secret))
    acc
  end

  defp extract_configs({:config, _, opts} = ast, acc, secret) do
    {_, val} = Macro.prewalk(opts, [], &get_config(&1, &2, secret))

    if is_list(val) && Enum.empty?(val) do
      {ast, acc}
    else
      {ast, [{ast, val}|acc]}
    end
  end
  defp extract_configs(ast, acc, secret) do
    {ast, acc}
  end

  defp get_config({secret, value} = ast, acc, secret), do: {ast, value}
  defp get_config(ast, acc, _), do: {ast, acc}

end