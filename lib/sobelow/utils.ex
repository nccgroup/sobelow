defmodule Sobelow.Utils do
  # General Utils
  def ast(filepath) do
    {:ok, ast} = Code.string_to_quoted(File.read!(filepath))
    ast
  end
  def print_code(fun, :highlight_all) do
    IO.puts "\n"
    IO.puts IO.ANSI.light_magenta() <> Macro.to_string(fun) <> IO.ANSI.reset()
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

  def get_erlang_funs_of_type(ast, type) do
    {_, acc} = Macro.prewalk(ast, [], &get_erlang_funs_of_type(&1, &2, type))
    acc
  end
  def get_erlang_funs_of_type({{:., _, [:erlang, type]}, _, _} = ast, acc, type) do
    {ast, [ast|acc]}
  end
  def get_erlang_funs_of_type(ast, acc, type), do: {ast, acc}

  ## This is used to get aliased function calls such as `File.read`
  ## or `Ecto.Adapters.SQL.query`.
  ##
  ## This splits the call between strict and and standard, because there
  ## are some instances where we can be more certain of the alias contents.
  ## For instance, when using stdlib features such as `File.read` the alias
  ## list will be [:File]. For functions like `Ecto.Adapters.SQL.query`, there is less
  ## certainty because the Module has likely been aliased. The alias list
  ## could be [:Ecto, :Adapters, :SQL], just [:SQL], or something else entirely.
  ##
  ## Will consider flagging strict/standard separately depending on how this
  ## works in practice.
  def get_aliased_funs_of_type(ast, type, module) when is_list(module) do
    {_, acc} = Macro.prewalk(ast, [], &get_strict_aliased_funs_of_type(&1, &2, type, module))
    acc
  end
  def get_aliased_funs_of_type(ast, type, module) do
    {_, acc} = Macro.prewalk(ast, [], &get_aliased_funs_of_type(&1, &2, type, module))
    acc
  end

  def get_strict_aliased_funs_of_type({{:., _, [{:__aliases__, _, aliases}, type]}, _, opts} = ast, acc, type, module) do
    if aliases === module do
      {ast, [ast|acc]}
    else
      {ast, acc}
    end
  end
  def get_strict_aliased_funs_of_type(ast, acc, type, module) do
    {ast, acc}
  end
  def get_aliased_funs_of_type({{:., _, [{:__aliases__, _, aliases}, type]}, _, opts} = ast, acc, type, module) do
    if List.last(aliases) === module do
      {ast, [ast|acc]}
    else
      {ast, acc}
    end
  end
  def get_aliased_funs_of_type(ast, acc, type, module) do
    {ast, acc}
  end

  def get_funs_of_type(ast, type) do
    {_, acc} = Macro.prewalk(ast, [], &get_funs_of_type(&1, &2, type))
    acc
  end
  def get_funs_of_type({type, _, _} = ast, acc, types) when is_list(types) do
    if Enum.member?(types, type) do
      {ast, [ast|acc]}
    else
      {ast, acc}
    end
  end
  def get_funs_of_type({type, _, _} = ast, acc, type) do
    {ast, [ast|acc]}
  end
  def get_funs_of_type(ast, acc, type), do: {ast, acc}

  ## Extract opts from piped functions separately.
  def extract_opts({:pipe, {:send_file, _, opts}}), do: parse_opts(Enum.at(opts, 1))
  def extract_opts({:pipe, {{:., _, [_, :query]}, _, opts}}), do: parse_opts(List.first(opts))

  def extract_opts({:send_file, _, opts} = fun), do: parse_opts(Enum.at(opts, 2))
  # Check for nil for `send_resp/1`
  def extract_opts({:send_resp, _, nil}), do: []
  def extract_opts({:send_resp, _, opts}), do: parse_opts(List.last(opts))
  ## This is what an ecto query looks like. Don't need to validate the aliases here,
  ## because that is done in the fetching phase.
  def extract_opts({{:., _, [_, :query]}, _, opts} = fun) do
    parse_opts(Enum.at(opts, 1))
  end
  def extract_opts({{:., _, [_, :send_file]}, _, opts} = fun) do
    parse_opts(Enum.at(opts, 2))
  end

  def extract_opts({_, _, opts} = fun) when is_list(opts) do
    opts
    |> Enum.map &parse_opts/1
  end
  def extract_opts(opts) when is_list(opts), do: Enum.map(opts, &parse_opts/1)

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
  # This is what an accessor func looks like, eg conn.params
  defp parse_opts({{:., _, [{val, _, nil}, _]}, _, _}), do: val
  defp parse_opts({fun, _, opts}) when fun in [:+, :-, :*, :/, :{}] do
    Enum.map(opts, &parse_opts/1)
  end
  # Sigils aren't ordinary function calls.
  defp parse_opts({fun, _, _}) when fun in [:sigil_s, :sigil_e], do: []
  defp parse_opts({fun, _, opts}) when is_list(opts), do: fun
  defp parse_opts(opts) when is_tuple(opts), do: parse_opts(Tuple.to_list(opts))
  defp parse_opts(opts) when is_list(opts), do: Enum.map(opts, &parse_opts/1)
  defp parse_opts(_), do: []

  def get_fun_declaration(fun) do
    {_, _, fun_opts} = fun
    [definition|_] = fun_opts
    declaration = case definition do
      {:when, _, [opts|_]} -> opts
      opts -> opts
    end
    params = get_params(declaration)
    {fun_name, line_no, _} = declaration

    {params, {fun_name, line_no}}
  end

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
    if File.exists?(filepath) do
      ast = ast(filepath)
      {_, project_block} = Macro.prewalk(ast, [], &extract_app_name/2)
      Atom.to_string(Keyword.get(project_block, :app))
    end
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

  def get_configs(key, filepath) do
    ast = ast(filepath)
    {ast, acc} = Macro.prewalk(ast, [], &extract_configs(&1, &2, key))
    acc
  end

  defp extract_configs({:config, _, opts} = ast, acc, key) do
    opt = List.last(opts)
    val = if is_list(opt), do: Keyword.get(opt, key), else: nil

    if is_nil(val) do
      {ast, acc}
    else
      {ast, [{ast, key, val}|acc]}
    end
  end
  defp extract_configs(ast, acc, key) do
    {ast, acc}
  end

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

  def is_content_type_html({:put_resp_content_type, _, opts}) do
    type_list = Enum.filter(opts, &is_binary/1)
    |> Enum.any?(&String.contains?(&1, "html"))
  end

  # The `render` function is parsed separately. This may change in the future,
  # but some unique properties made it simpler to start with this.
  def parse_render_opts({:render, _, opts}, params, meta) do
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

  # Traversal Utils

  # Misc Utils

end