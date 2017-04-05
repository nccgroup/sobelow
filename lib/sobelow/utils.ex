defmodule Sobelow.Utils do
def get_routes(filepath) do
    {:ok, ast} = ast(filepath)
    {:defmodule, _, module_opts} = ast
    do_block = get_do_block(module_opts)
    {_, _, fun_list} = do_block

    scopes = get_funs_of_type(fun_list, :scope)
    |> List.flatten
    |> extract_scopes
  end

  defp extract_scopes(scopes) do
    IO.inspect Enum.map(scopes, &extract_scope(&1))
  end

  defp extract_scope({:scope, _, [route, _, [do: block]]}) do
    {route, block}
  end
  defp extract_scope({:scope, _, [route, _, _, [do: block]]}) do
    {route, block}
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

  defp ast(filepath) do
    Code.string_to_quoted(File.read!(filepath))
  end
end