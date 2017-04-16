defmodule Sobelow.Utils do
  # General Utils
  def ast(filepath) do
    {:ok, ast} = Code.string_to_quoted(File.read!(filepath))
    ast
  end

  def print_code(fun) do
    IO.puts "\n"
    IO.puts Macro.to_string(fun)
  end

  ## Function parsing
  def get_def_funs(filepath) do
    ast = ast(filepath)
    get_funs_of_type(ast, [:def, :defp])
  end

  defp get_aliased_funs_of_type(ast, type, module) do
    {_, acc} = Macro.prewalk(ast, [], &get_aliased_funs_of_type(&1, &2, type, module))
    acc
  end
  defp get_aliased_funs_of_type({{:., _, [{:__aliases__, _, aliases}, type]}, _, opts} = ast, acc, type, module) do
    if Enum.member?(aliases, module) do
      {ast, [ast|acc]}
    else
      {ast, acc}
    end
  end
  defp get_aliased_funs_of_type(ast, acc, type, module) do
    {ast, acc}
  end

  defp get_funs_of_type(ast, type) do
    {_, acc} = Macro.prewalk(ast, [], &get_funs_of_type(&1, &2, type))
    acc
  end
  defp get_funs_of_type({type, _, _} = ast, acc, types) when is_list(types) do
    if Enum.member?(types, type) do
      {ast, [ast|acc]}
    else
      {ast, acc}
    end
  end
  defp get_funs_of_type({type, _, _} = ast, acc, type) do
    {ast, [ast|acc]}
  end
  defp get_funs_of_type(ast, acc, type), do: {ast, acc}

  ## Get function parameters.
  defp get_params({_, _, params}) when is_list(params) do
    Enum.flat_map(params, &get_params/1)
  end
  defp get_params({_, params}) when is_tuple(params) do
    get_params(params)
  end
  defp get_params({var, _, nil}), do: [var]
  defp get_params(_), do: []

  ## Parsing string interpolation got really messy when attempting to
  ## use the Macro functionality. Will stick with this for now.
  defp parse_string_interpolation({key, _, nil}), do: key
  defp parse_string_interpolation({:::, _, opts}) do
    parse_string_interpolation(opts)
  end
  defp parse_string_interpolation([{{:., _, [Kernel, :to_string]}, _, vars}, _] = opts) do
    Enum.map vars, &parse_string_interpolation/1
  end
  defp parse_string_interpolation({key, _, opts}) when key in [:+, :-, :*, :/] do
    Enum.map opts, &parse_string_interpolation/1
  end
  defp parse_string_interpolation({{:., _, [Kernel, :to_string]}, _, opts}) do
    Enum.map opts, &parse_string_interpolation/1
  end
  defp parse_string_interpolation({{:., _, [{:__aliases__, _, module}, func]}, _, _}) do
    Module.concat(module)
  end
  defp parse_string_interpolation({:<<>>, _, opts}) do
    opts
    |> Enum.map(&parse_string_interpolation/1)
  end
  defp parse_string_interpolation({key, _, _} = opts) do
    key
  end
  defp parse_string_interpolation(_) do
    []
  end

  ## File listing
  def all_files(filepath, directory \\ "") do
    {:ok, files} = File.ls(filepath)
    Enum.flat_map(files, &list_files(&1, filepath, directory))
  end
  defp list_files(filename, filepath, directory) do
    cond do
      Path.extname(filename) === ".ex" ->
        [directory <> "/" <> filename]
      File.dir?(filepath <> filename) ->
        all_files(filepath <> filename <> "/", directory <> "/" <> filename)
      true ->
        []
    end
  end

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

  # XSS Utils

  def get_template_raw_vars(filepath) do
    ast = EEx.compile_string(File.read!(filepath))

    {_, acc} = Macro.prewalk(ast, [], &extract_raw_vars(&1, &2))

    acc
  end
  defp extract_raw_vars({:raw, _, [{_, _, [_, raw]}]} = ast, acc) do
    {ast, [raw|acc]}
  end
  defp extract_raw_vars(ast, acc), do: {ast, acc}

  ## Collection of functions to pull options from `send_resp` call.
  def parse_send_resp_def(fun) do
    {_, _, fun_opts} = fun
    [declaration|_] = fun_opts
    params = get_params(declaration)
    {fun_name, line_no, _} = declaration

    resps = get_funs_of_type(fun, :send_resp)
    |> Enum.map(&parse_send_resp_opts/1)

    is_html = get_funs_of_type(fun, :put_resp_content_type)
    |> Enum.any?(&is_content_type_html/1)

    {resps, is_html, params, {fun_name, line_no}}
  end

  defp parse_send_resp_opts({:send_file, _, opts}) do
    parse_send_resp_opts(opts)
  end
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
  defp parse_send_resp_opts({{:., _, [Access, :get]}, _, [{{:., _, [{:conn, _, nil}, :params]}, _, _}, _]}) do
    "conn.params"
  end
  defp parse_send_resp_opts({{:., _, [{:__aliases__, _, module}, func]}, _, _}) do
    Module.concat(module)
  end
  defp parse_send_resp_opts(_), do: nil

  defp is_content_type_html({:put_resp_content_type, _, opts}) do
    type_list = Enum.filter(opts, &is_binary/1)
    |> Enum.any?(&String.contains?(&1, "html"))
  end

  ## Collection of functions to pull options from the `render` call.
  def parse_render_def(fun) do
    {_, _, fun_opts} = fun
    [declaration|_] = fun_opts
    params = get_params(declaration)
    {fun_name, line_no, _} = declaration

    get_funs_of_type(fun, :render)
    |> Enum.map(&parse_render_opts(&1, params, {fun_name, line_no}))
  end

  defp parse_render_opts({:render, _, opts}, params, meta) do
    opts = Enum.reject(opts, fn opt -> is_tuple(opt) end)
    [template|vars] =
      case Enum.empty?(opts) do
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

  defp is_reflected_var?({_, {_, _, nil}}), do: true
  defp is_reflected_var?(_), do: false

  defp is_in_params?({_, {var, _, _}}, params) do
    Enum.member?(params, var)
  end

  def is_conn_params?({_, {{:., _, [Access, :get]}, _, access_opts}}), do: is_conn_params?(access_opts)
  def is_conn_params?([{{:., _, [{:conn, _, nil}, :params]}, _, []}, _]), do: true
  def is_conn_params?(_), do: false

  # SQL Utils

  def parse_sql_def(fun) do
    {_, _, fun_opts} = fun
    [declaration|_] = fun_opts
    params = get_params(declaration)
    {fun_name, line_no, _} = declaration

    interp_vars = get_aliased_funs_of_type(fun, :query, :SQL)
    |> Enum.map(&extract_sql_opts/1)
    |> List.flatten

    {interp_vars, params, {fun_name, line_no}}
  end

  defp extract_sql_opts({_, _, opts}) when is_list(opts) do
    parse_sql_opts(opts)
  end

  defp parse_sql_opts({:<<>>, _, _} = fun) do
    parse_string_interpolation(fun)
  end
  defp parse_sql_opts([{:__aliases__, _, aliases}|[sql|_]]), do: parse_sql_opts(sql)

  defp parse_sql_opts([sql|_]), do: parse_sql_opts(sql)
  defp parse_sql_opts({key, _, nil}), do: key
  defp parse_sql_opts(_), do: []

  # Traversal Utils
  def parse_send_file_def(fun) do
    {_, _, fun_opts} = fun
    [declaration|_] = fun_opts
    params = get_params(declaration)
    {fun_name, line_no, _} = declaration

    files = get_funs_of_type(fun, :send_file)
    |> Enum.map(&parse_send_resp_opts/1)
    |> List.flatten

    {files, params, {fun_name, line_no}}
  end

  def parse_file_read_def(fun) do
    {_, _, fun_opts} = fun
    [declaration|_] = fun_opts
    params = get_params(declaration)
    {fun_name, line_no, _} = declaration

    resps = get_aliased_funs_of_type(fun, :read, :File)
    |> Enum.map(&extract_file_read_opts/1)
    |> List.flatten

    {resps, params, {fun_name, line_no}}
  end

  defp extract_file_read_opts({_, _, opts} = fun) when is_list(opts) do
    parse_file_opts(opts)
  end

  defp parse_file_opts({:<<>>, _, _} = fun) do
    parse_string_interpolation(fun)
  end
  defp parse_file_opts([{:__aliases__, _, aliases}|[file|_]]) do
    if Enum.member?(aliases, :File) do
      parse_file_opts(file)
    else
      []
    end
  end
  defp parse_file_opts([file|_]), do: parse_file_opts(file)
  defp parse_file_opts({key, _, nil}), do: key
  defp parse_file_opts(_), do: []

end