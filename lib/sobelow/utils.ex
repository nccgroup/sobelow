defmodule Sobelow.Utils do
  require IEx
  def get_app_name(filepath) do
    {:ok, ast} = ast(filepath)
    {:defmodule, _, module_opts} = ast
    do_block = get_do_block(module_opts)
    {_, _, fun_list} = do_block

    get_funs_of_type(fun_list, :def)
    |> List.flatten
    |> Enum.find_value(&extract_app_name/1)
    |> Atom.to_string
  end

  defp extract_app_name({:def, _, opts}) do
    extract_app_name(opts)
  end
  defp extract_app_name([{:project, _, _}, [do: block]]) do
    Keyword.get(block, :app)
  end
  defp extract_app_name(_), do: false

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

  def get_template_raw_vars(filepath) do
    ast = EEx.compile_string(File.read!(filepath))
    get_funs_of_type(ast, :raw)
    |> List.flatten
    |> Enum.map(&parse_raw_vars(&1))
  end

  def parse_sql_def(fun) when is_tuple(fun) do
    {_, _, fun_opts} = fun
    [declaration|_] = fun_opts
    do_block = get_do_block(fun_opts)
    params = get_params(declaration)
    {fun_name, line_no, _} = declaration

    interp_vars = get_aliased_funs_of_type(do_block, :query)
    |> List.flatten

    {interp_vars, params, {fun_name, line_no}}
  end

  def parse_fun_def(fun) when is_tuple(fun) do
    {_, _, fun_opts} = fun
    [declaration|_] = fun_opts
    do_block = get_do_block(fun_opts)
    params = get_params(declaration)
    {fun_name, line_no, _} = declaration

    # This pulls assigns from a function, but it wasn't
    # ultimately needed. Not removing for now.
    # assigns = get_funs_of_type(do_block, :=)
    # |> Enum.map(&parse_assign_opts/1)
    # |> List.flatten

    get_funs_of_type(do_block, :render)
    |> List.flatten
    |> Enum.map(&parse_render_opts(&1, params, {fun_name, line_no}))
  end

  def parse_send_resp_def(fun) when is_tuple(fun) do
    {_, _, fun_opts} = fun
    [declaration|_] = fun_opts
    do_block = get_do_block(fun_opts)
    params = get_params(declaration)
    {fun_name, line_no, _} = declaration

    resps = get_funs_of_type(do_block, :send_resp)
    |> List.flatten
    |> Enum.map(&parse_send_resp_opts/1)
    |> Enum.reject(&is_nil/1)

    is_html = get_funs_of_type(do_block, :put_resp_content_type)
    |> List.flatten
    |> Enum.any?(&is_content_type_html/1)

    {resps, is_html, params, {fun_name, line_no}}
  end

  defp is_content_type_html({:put_resp_content_type, _, opts}) do
    type_list = Enum.filter(opts, &is_binary/1)
    |> Enum.any?(&String.contains?(&1, "html"))
  end

  defp parse_assign_opts({:=, _, [left, _]}) do
    parse_assign_opts(left)
  end
  defp parse_assign_opts({var, _, nil}) do
    var
  end
  defp parse_assign_opts(left) when is_list(left) do
    Enum.map(left, &parse_assign_opts/1)
  end
  defp parse_assign_opts({fun, _, opts}) when is_atom(fun) do
    parse_assign_opts(opts)
  end
  defp parse_assign_opts(left) when is_tuple(left) do
    parse_assign_opts(Tuple.to_list(left))
  end
  defp parse_assign_opts(left) when is_atom(left) do
    []
  end

  defp parse_raw_vars({:raw, _, [{_, _, [_, raw]}]}) do
    raw
  end
  defp parse_raw_vars(_), do: []

  defp parse_send_resp_opts({:send_resp, _, opts}) do
    parse_send_resp_opts(opts)
  end
  defp parse_send_resp_opts([_, _, val]) do
    parse_send_resp_opts(val)
  end
  defp parse_send_resp_opts([_, val]), do: parse_send_resp_opts(val)
  defp parse_send_resp_opts({key, _, nil}), do: key
  defp parse_send_resp_opts({:<<>>, _, [{_, _, opts}]}) do
    Enum.drop(opts, -1)
    |> Enum.map(&parse_string_interpolation/1)
    |> List.flatten
  end
  defp parse_send_resp_opts({:<<>>, _, opts}) do
    Enum.map(opts, &parse_string_interpolation/1)
    |> List.flatten
  end

  # This is a general weak-confidence trap for string interpolation
  # or other function calls. There is more that can be done to get
  # more precise confidence, but I would like to see how much it is
  # actually needed before going too deep.
  defp parse_send_resp_opts({_, _, _} = opts), do: opts
  defp parse_send_resp_opts(_), do: nil

  defp parse_string_interpolation({key, _, nil}), do: key
  defp parse_string_interpolation({_, _, [{key, _, nil}]}), do: key
  defp parse_string_interpolation({_, _, [{_, _, opts}]}) do
    Enum.map opts, &parse_string_interpolation/1
  end
  defp parse_string_interpolation({_, _, opts}) do
    Enum.drop(opts, -1)
    |> Enum.map(&parse_string_interpolation/1)
  end
  defp parse_string_interpolation({:::, _, opts}), do: parse_string_interpolation(opts)
  defp parse_string_interpolation(v), do: []

  defp parse_render_opts({:render, _, opts}, params, meta) do
    opts = Enum.reject(opts, fn opt -> is_tuple(opt) end)
    [template|vars] = case Enum.empty?(opts) do
      false ->
        opts
      true ->
        ["", []]
    end
    if !Enum.empty?(vars) do
      [vars|_] = vars
    end

    reflected_vars = Enum.filter(vars, fn var ->
      (is_reflected_var?(var) && is_in_params?(var, params)) || is_conn_params?(var)
    end)

    var_keys = Keyword.keys(vars)
    reflected_var_keys = Keyword.keys(reflected_vars)

    {template, reflected_var_keys, var_keys -- reflected_var_keys, params, meta}
  end
  defp parse_render_opts([]), do: []

  defp is_reflected_var?({_, {_, _, nil}}), do: true
  defp is_reflected_var?(_), do: false

  defp is_in_params?({_, {var, _, _}}, params) do
    if Enum.member?(params, var) do
      true
    else
      false
    end
  end

  def is_conn_params?({_, {{:., _, [Access, :get]}, _, access_opts}}), do: is_conn_params?(access_opts)
  def is_conn_params?([{{:., _, [{:conn, _, nil}, :params]}, _, []}, _]), do: true
  def is_conn_params?(_), do: false

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

  defp get_aliased_funs_of_type({{:., _, [{:__aliases__, _, aliases}, type]}, _, opts}, type) do
    if List.last(aliases) == :SQL do
      Enum.map(opts, &parse_string_interpolation/1) |> List.flatten
    else
      []
    end
  end
  defp get_aliased_funs_of_type({_, _, opts}, type) when is_list(opts) do
    Enum.map(opts, &get_aliased_funs_of_type(&1, type))
  end
  defp get_aliased_funs_of_type(_, _), do: []

  defp get_funs_of_type({type, _, _} = fun, type) do
    [fun]
  end
  defp get_funs_of_type({_, _, opts}, type) when is_list(opts) do
    get_funs_of_type(opts, type)
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
  defp get_funs_of_type(_,_), do: []

  defp get_fun_of_type({type, _, _} = fun, type) do
    fun
  end
  defp get_fun_of_type({_,_,opts}, type) when is_list(opts) do
    get_funs_of_type(opts, type)
  end
  defp get_fun_of_type([do: block], type) do
    if is_list(block) do
      get_funs_of_type(block, type)
    else
      get_fun_of_type(block, type)
    end
  end
  defp get_fun_of_type([do: do_block, else: else_block], type) do
    do_b = get_fun_of_type(do_block, type)
    else_b = get_fun_of_type(else_block, type)

    do_b = if do_b && is_list(do_b) do
      do_b
    end

    else_b = if else_b && is_list(else_b) do
      else_b
    end

    (do_b || []) ++ (else_b || [])
  end
  defp get_fun_of_type(_,_), do: false

  defp get_do_block([do: block]), do: block
  defp get_do_block(opts) when is_list(opts), do: Enum.find_value(opts, &get_do_block(&1))
  defp get_do_block({_,_,opts}) when is_list(opts), do: get_do_block(opts)
  defp get_do_block(v), do: false

  defp get_params({_, _, params}) when is_list(params) do
    Enum.flat_map(params, &get_params/1)
  end
  defp get_params({_, params}) when is_tuple(params) do
    get_params(params)
  end
  defp get_params({var, _, nil}), do: [var]
  defp get_params(_), do: []

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

  def all_files(filepath, directory \\ "") do
    {:ok, files} = File.ls(filepath)
    Enum.flat_map(files, &list(&1, filepath, directory))
  end

  defp list(filename, filepath, directory) do
    cond do
      String.contains?(filename, "_controller.ex") ->
        [directory <> "/" <> filename]
      String.contains?(filename, ".ex") ->
        []
      true ->
        all_files(filepath <> filename <> "/", directory <> "/" <> filename)
    end
  end

end