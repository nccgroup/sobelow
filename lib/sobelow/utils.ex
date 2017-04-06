defmodule Sobelow.Utils do

  def get_app_name(filepath) do
    {:ok, ast} = ast(filepath)
    {:defmodule, _, [aliases|_]} = ast
    {:__aliases__, _, module_name} = aliases
    [app_name|_] = module_name
    Atom.to_string(app_name)
  end

  def get_routes(filepath) do
    {:ok, ast} = ast(filepath)
    {:defmodule, _, module_opts} = ast
    do_block = get_do_block(module_opts)
    {_, _, fun_list} = do_block

    get_funs_of_type(fun_list, :scope)
    |> List.flatten
    |> extract_scopes
  end

  def get_def_funs(filepath) do
    {:ok, ast} = ast(filepath)
    {:defmodule, _, module_opts} = ast
    do_block = get_do_block(module_opts)
    {_, _, fun_list} = do_block

    get_funs_of_type(fun_list, [:def, :defp])
    |> List.flatten
  end

  def parse_fun(fun) do
#    {_, _, fun_opts} = fun
#    do_block = get_do_block(fun_opts)
    fun
  end

  defp extract_scopes(scopes) do
    Enum.map(scopes, &extract_scope(&1))
    |> Enum.reduce(%{}, &merge_scope(&1, &2))
  end

  defp merge_scope({mod, block}, acc) do
    if current_block = Map.get(acc, mod) do
      Map.update(acc, mod, block, fn _ -> current_block ++ block end)
    else
      Map.put(acc, mod, block)
    end
  end

  defp extract_scope({:scope, _, [_route, {:__aliases__, _, module_name}, [do: block]]}) do
    {Module.concat(module_name), [block]}
  end
  defp extract_scope({:scope, _, [_route, {:__aliases__, _, module_name}, _, [do: block]]}) do
    {Module.concat(module_name), [block]}
  end

  defp get_funs_of_type(fun_list, type) when is_list(type) do
    Enum.map type, &get_funs_of_type(fun_list, &1)
  end

  defp get_funs_of_type(fun_list, type) when is_list(fun_list) do
    Enum.reduce fun_list, [], fn(fun, acc) ->
      if val = get_fun_of_type(fun, type) do
        [val|acc]
      else
        acc
      end
    end
  end

  defp get_fun_of_type({type, _, _} = fun, type) do
    fun
  end
  defp get_fun_of_type({_,_,opts}, type) when is_list(opts) do
    get_funs_of_type(opts, type)
  end
  defp get_fun_of_type([do: block], type) do
    get_fun_of_type(block, type)
  end
  defp get_fun_of_type(_,_), do: false

  defp get_do_block([do: block]), do: block
  defp get_do_block(opts) when is_list(opts), do: Enum.find_value(opts, &get_do_block(&1))
  defp get_do_block({_,_,opts}) when is_list(opts), do: get_do_block(opts)
  defp get_do_block(_), do: false

  # Config related funcs
  def get_configs(key, filepath) do
    {:ok, {_, _, terms}} = ast(filepath)
    Enum.map(terms, &get_config_val(&1, key))
      |> Enum.filter(fn val -> val end)
  end

  defp get_config_val(term, key) do
    if val = get_val(term, key) do
      {term, val}
    end
  end

  defp get_val({:config, _, opts}, key), do: get_val(opts, key)
  defp get_val(opts, key) when is_list(opts) do
    Enum.find_value(opts, &get_val(&1, key))
  end
  defp get_val({key, val}, key), do: val
  defp get_val(_, _), do: false

  def ast(filepath) do
    Code.string_to_quoted(File.read!(filepath))
  end
end