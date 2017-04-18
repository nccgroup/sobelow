defmodule Sobelow.Utils do
  # General Utils
  def ast(filepath) do
    {:ok, ast} = Code.string_to_quoted(File.read!(filepath))
    ast
  end

  def print_code(fun, var, call \\ nil) do
    acc = ""
    func_string = Macro.to_string fun, fn ast, string ->
      s = case ast do
        {^call, _, _} ->
          if is_fun_with_var?(ast, var) do
            IO.ANSI.light_magenta() <> string <> IO.ANSI.reset()
          else
            string
          end
        {{:., _,[{:__aliases__, _, aliases}, ^call]}, _, _} ->
          if is_fun_with_var?(ast, var) do
            IO.ANSI.light_magenta() <> string <> IO.ANSI.reset()
          else
            string
          end
        {{:., _, [:erlang, ^call]}, _, _} ->
          if is_fun_with_var?(ast, var) do
            IO.ANSI.light_magenta() <> string <> IO.ANSI.reset()
          else
            string
          end
        _ -> string
      end
      acc <> s
    end

    IO.puts "\n"
    IO.puts func_string
  end

  def is_fun_with_var?(fun, var) do
    {_, acc} = Macro.prewalk(fun, [], &is_fun_var/2)
    if Enum.member?(acc, var), do: true, else: false
  end

  defp is_fun_var({var, _, nil} = ast, acc), do: {ast, [var|acc]}
  defp is_fun_var({:__aliases__, _, aliases} = ast, acc) do
    {ast, [Module.concat(aliases)|acc]}
  end
  defp is_fun_var({:render, _, [_, _, keylist]} = ast, acc) do
    {ast, Keyword.keys(keylist) ++ acc}
  end
  defp is_fun_var({:render, _, [_, keylist]} = ast, acc) when is_list(keylist) do
    {ast, Keyword.keys(keylist) ++ acc}
  end
  defp is_fun_var(ast, acc), do: {ast, acc}

  def find_call({call, _, _} = ast, acc, call) do
    {ast, acc <> Macro.to_string(ast)}
  end
  def find_call(ast, acc, call), do: {ast, acc <> Macro.to_string(ast)}

  ## Function parsing
  def get_def_funs(filepath) do
    ast = ast(filepath)
    get_funs_of_type(ast, [:def, :defp])
  end

  defp get_erlang_funs_of_type(ast, type) do
    {_, acc} = Macro.prewalk(ast, [], &get_erlang_funs_of_type(&1, &2, type))
    acc
  end
  defp get_erlang_funs_of_type({{:., _, [:erlang, type]}, _, _} = ast, acc, type) do
    {ast, [ast|acc]}
  end
  defp get_erlang_funs_of_type(ast, acc, type), do: {ast, acc}

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

  ## Extract opts from piped functions separately.
  defp extract_opts({:pipe, {:send_file, _, opts}}), do: parse_opts(Enum.at(opts, 1))
  defp extract_opts({:pipe, {{:., _, [_, :query]}, _, opts}}), do: parse_opts(List.first(opts))

  defp extract_opts({:send_file, _, opts} = fun), do: parse_opts(Enum.at(opts, 2))
  defp extract_opts({:send_resp, _, opts}), do: parse_opts(List.last(opts))
  ## This is what an ecto query looks like. Don't need to validate the aliases here,
  ## because that is done in the fetching phase.
  defp extract_opts({{:., _, [_, :query]}, _, opts} = fun) do
    parse_opts(Enum.at(opts, 1))
  end

  defp extract_opts({_, _, opts} = fun) when is_list(opts) do
    opts
    |> Enum.map &parse_opts/1
  end
  defp extract_opts(opts) when is_list(opts), do: Enum.map(opts, &parse_opts/1)

  defp parse_opts({key, _, nil}), do: key
  defp parse_opts({:<<>>, _, opts}) do
    Enum.map(opts, &parse_string_interpolation/1)
    |> List.flatten
  end
  defp parse_opts({{:., _, [Access, :get]}, _, [{{:., _, [{:conn, _, nil}, :params]}, _, _}, _]}) do
    "conn.params"
  end
  defp parse_opts({{:., _, [Access, :get]}, _, opts}) do
    [{val, _, _}|_] = opts
    val
  end
  defp parse_opts({{:., _, [{:__aliases__, _, module}, func]}, _, _}) do
    Module.concat(module)
  end
  defp parse_opts({fun, _, opts}) when fun in [:+, :-, :*, :/, :{}] do
    Enum.map(opts, &parse_opts/1)
  end
  # Sigils aren't ordinary function calls.
  defp parse_opts({fun, _, _}) when fun in [:sigil_s, :sigil_e], do: []
  defp parse_opts({fun, _, opts}) when is_list(opts), do: fun
  defp parse_opts(opts) when is_tuple(opts), do: parse_opts(Tuple.to_list(opts))
  defp parse_opts(opts) when is_list(opts), do: Enum.map(opts, &parse_opts/1)
  defp parse_opts(_), do: []

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

  def parse_send_resp_def(fun) do
    {_, _, fun_opts} = fun
    [declaration|_] = fun_opts
    params = get_params(declaration)
    {fun_name, line_no, _} = declaration

    resps = get_funs_of_type(fun, :send_resp)
    |> Enum.map(&extract_opts/1)

    is_html = get_funs_of_type(fun, :put_resp_content_type)
    |> Enum.any?(&is_content_type_html/1)

    {resps, is_html, params, {fun_name, line_no}}
  end

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

  # The `render` function is parsed separately. This may change in the future,
  # but some unique properties made it simpler to start with this.
  defp parse_render_opts({:render, _, opts}, params, meta) do
    # Reject tuple vals from opts. Basically, this will leave the template
    # and the keyword list if there is one.
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

    var_keys =
      Enum.map vars, fn {key, val} ->
        if !is_binary(val), do: key
      end

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

  ## query(repo, sql, params \\ [], opts \\ [])
  ##
  ## ecto queries have optional params, so they must be
  ## handled differently.
  def parse_sql_def(fun) do
    {_, _, fun_opts} = fun
    [declaration|_] = fun_opts
    params = get_params(declaration)
    {fun_name, line_no, _} = declaration

    pipevars = get_funs_of_type(fun, :|>)
    |> Enum.map(fn {_, _, opts} -> Enum.at(opts, 1) end)
    |> Enum.flat_map(&get_aliased_funs_of_type(&1, :query, :SQL))
    |> Enum.map(&extract_opts({:pipe, &1}))
    |> List.flatten

    interp_vars = get_aliased_funs_of_type(fun, :query, :SQL) -- pipevars
    |> Enum.map(&extract_opts/1)
    |> List.flatten

    {interp_vars ++ pipevars, params, {fun_name, line_no}}
  end

  # Traversal Utils

  ## send_file(conn, status, file, offset \\ 0, length \\ :all)
  ##
  ## send_file has optional params, so the parameter we care about
  ## for traversal won't be at a definite location. This is a
  ## simple solution to the problem.
  def parse_send_file_def(fun) do
    {_, _, fun_opts} = fun
    [declaration|_] = fun_opts
    params = get_params(declaration)
    {fun_name, line_no, _} = declaration

    pipefiles = get_funs_of_type(fun, :|>)
    |> Enum.map(fn {_, _, opts} -> Enum.at(opts, 1) end)
    |> Enum.flat_map(&get_funs_of_type(&1, :send_file))
    |> Enum.map(&extract_opts({:pipe, &1}))
    |> List.flatten

    files = get_funs_of_type(fun, :send_file) -- pipefiles
    |> Enum.map(&extract_opts/1)
    |> List.flatten


    {files ++ pipefiles, params, {fun_name, line_no}}
  end

  def parse_file_read_def(fun) do
    {_, _, fun_opts} = fun
    [declaration|_] = fun_opts
    params = get_params(declaration)
    {fun_name, line_no, _} = declaration

    resps = get_aliased_funs_of_type(fun, :read, :File)
    |> Enum.map(&extract_opts/1)
    |> List.flatten

    {resps, params, {fun_name, line_no}}
  end

  # Misc Utils
  def parse_binary_term_def(fun) do
    {_, _, fun_opts} = fun
    [declaration|_] = fun_opts
    params = get_params(declaration)
    {fun_name, line_no, _} = declaration

    erls = get_erlang_funs_of_type(fun, :binary_to_term)
    |> Enum.map(&extract_opts/1)
    |> List.flatten

    {erls, params, {fun_name, line_no}}
  end
end