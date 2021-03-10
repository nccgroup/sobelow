defmodule Sobelow.Parse do
  @moduledoc false

  @operators [
    :+,
    :-,
    :!,
    :^,
    :not,
    :~~~,
    :*,
    :/,
    :++,
    :--,
    :..,
    :<>,
    :<<<,
    :>>>,
    :~>>,
    :<<~,
    :>,
    :<,
    :>=,
    :<=,
    :==,
    :!=,
    :=~,
    :===,
    :!==,
    :&&,
    :&&&,
    :and,
    :||,
    :|||,
    :or,
    :=,
    :|
  ]

  def ast(filepath) do
    case Code.string_to_quoted(read_file(filepath), columns: true, file: filepath) do
      {:ok, ast} ->
        ast

      {:error, {line, err, _}} ->
        if Application.get_env(:sobelow, :strict) do
          IO.puts(:stderr, "#{filepath}:#{line}: #{err}")
          System.halt(2)
        else
          {}
        end
    end
  end

  defp read_file(filepath) do
    content = File.read!(filepath)

    if Sobelow.get_env(:skip) do
      String.replace(
        content,
        ~r/#\s?sobelow_skip (\[(\"[^"]+\"(,|, )?)+\])/,
        "@sobelow_skip \\g{1}"
      )
    else
      content
    end
  end

  def get_meta_funs(filepath) when is_binary(filepath) do
    ast = ast(filepath)
    get_meta_funs(ast)
  end

  def get_meta_funs(ast) do
    init_acc = %{def_funs: [], use_funs: [], module_attrs: []}
    {_, acc} = Macro.prewalk(ast, init_acc, &get_meta_funs(&1, &2))
    acc
  end

  def get_meta_funs({:@, _, [{:sobelow_skip, _, _}]} = ast, acc) do
    if Sobelow.get_env(:skip) do
      {ast, Map.update!(acc, :def_funs, &[ast | &1])}
    else
      {ast, acc}
    end
  end

  def get_meta_funs({:def, _, nil} = ast, acc), do: {ast, acc}
  def get_meta_funs({:defp, _, nil} = ast, acc), do: {ast, acc}
  def get_meta_funs({:@, _, [{_, _, nil}]} = ast, acc), do: {ast, acc}

  def get_meta_funs({:def, _, _} = ast, acc) do
    {ast, Map.update!(acc, :def_funs, &[ast | &1])}
  end

  def get_meta_funs({:defp, _, _} = ast, acc) do
    {ast, Map.update!(acc, :def_funs, &[ast | &1])}
  end

  def get_meta_funs({:use, _, _} = ast, acc) do
    {ast, Map.update!(acc, :use_funs, &[ast | &1])}
  end

  def get_meta_funs({:@, _, [attr | _]} = ast, acc) do
    {ast, Map.update!(acc, :module_attrs, &[attr | &1])}
  end

  def get_meta_funs(ast, acc), do: {ast, acc}

  def get_meta_template_funs(filepath) do
    ast = EEx.compile_string(File.read!(filepath))
    get_meta_template_fun(ast)
  end

  def get_meta_template_fun(ast) do
    init_acc = %{raw: [], ast: ast}
    {_, acc} = Macro.prewalk(ast, init_acc, &get_meta_template_fun(&1, &2))
    acc
  end

  # This is some minor code duplication, but feels worth it
  def get_meta_template_fun({:|>, _, [_, {:raw, _, _}]} = ast, acc) do
    {ast, Map.update!(acc, :raw, &[ast | &1])}
  end

  def get_meta_template_fun({:raw, _, _} = ast, acc) do
    {ast, Map.update!(acc, :raw, &[ast | &1])}
  end

  def get_meta_template_fun(ast, acc), do: {ast, acc}

  def get_fun_vars_and_meta(fun, idx, type, module) do
    {params, {fun_name, line_no}} = get_fun_declaration(fun)

    pipefuns = get_funs_from_pipe(fun, type, module)
    pipevars = get_pipefuns_vars(pipefuns, fun, idx)

    vars =
      (get_funs(fun, type, module) -- pipefuns)
      |> get_funs_vars(idx, type, module)

    {vars ++ pipevars, params, {fun_name, line_no}}
  end

  def get_erlang_fun_vars_and_meta(fun, idx, type, module) do
    {params, {fun_name, line_no}} = get_fun_declaration(fun)

    pipefuns = get_erlang_funs_from_pipe(fun, type, module)
    pipevars = get_pipefuns_vars(pipefuns, fun, idx)

    vars =
      (get_erlang_aliased_funs_of_type(fun, type, module) -- pipefuns)
      |> get_funs_vars(idx, type, module)

    {vars ++ pipevars, params, {fun_name, line_no}}
  end

  defp get_funs(fun, type, nil) do
    get_funs_of_type(fun, type)
  end

  defp get_funs(fun, type, module) when is_list(module) do
    get_aliased_funs_of_type(fun, type, module)
  end

  defp get_funs(fun, type, {:required, module}) do
    get_aliased_funs_of_type(fun, type, module)
  end

  defp get_funs(fun, type, module) do
    get_funs(fun, type, {:required, module}) ++ get_funs_of_type(fun, type)
  end

  defp get_funs_from_pipe(fun, type, nil) do
    get_pipe_funs(fun)
    |> Enum.map(fn {_, _, opts} -> Enum.at(opts, 1) end)
    |> Enum.flat_map(&get_piped_funs_of_type(&1, type))
    |> Enum.uniq()
  end

  defp get_funs_from_pipe(fun, type, module) when is_list(module) do
    get_pipe_funs(fun)
    |> Enum.map(fn {_, _, opts} -> Enum.at(opts, 1) end)
    |> Enum.flat_map(&get_piped_aliased_funs_of_type(&1, type, module))
    |> Enum.uniq()
  end

  defp get_funs_from_pipe(fun, type, {:required, module}) do
    get_pipe_funs(fun)
    |> Enum.map(fn {_, _, opts} -> Enum.at(opts, 1) end)
    |> Enum.flat_map(&get_piped_aliased_funs_of_type(&1, type, module))
    |> Enum.uniq()
  end

  defp get_funs_from_pipe(fun, type, module) do
    get_funs_from_pipe(fun, type, {:required, module}) ++ get_funs_from_pipe(fun, type, nil)
  end

  def get_erlang_funs_from_pipe(fun, type, module) do
    get_pipe_funs(fun)
    |> Enum.map(fn {_, _, opts} -> Enum.at(opts, 1) end)
    |> Enum.flat_map(&get_piped_erlang_aliased_funs_of_type(&1, type, module))
    |> Enum.uniq()
  end

  defp get_funs_vars(funs, idx, _type, _module) do
    funs
    |> Enum.map(&{&1, extract_opts(&1, idx)})
    |> Enum.map(&normalize_finding/1)
    |> Enum.reject(fn {_, vars} ->
      is_list(vars) && Enum.empty?(vars)
    end)
  end

  defp get_pipefuns_vars(pipefuns, fun, 0) do
    pipefuns
    |> Enum.map(&{&1, get_pipe_val(fun, &1)})
    |> Enum.map(&normalize_finding/1)
    |> Enum.reject(fn {_, vars} ->
      is_list(vars) && Enum.empty?(vars)
    end)
  end

  defp get_pipefuns_vars(pipefuns, _fun, idx) do
    idx = idx - 1

    pipefuns
    |> Enum.map(&{&1, extract_opts(&1, idx)})
    |> Enum.map(&normalize_finding/1)
    |> Enum.reject(fn {_, vars} ->
      is_list(vars) && Enum.empty?(vars)
    end)
  end

  def normalize_finding({finding, opts}) when is_list(opts) do
    {finding, List.flatten(opts)}
  end

  def normalize_finding({finding, opt}) do
    {finding, [opt]}
  end

  def get_erlang_funs_of_type(ast, type) do
    {_, acc} = Macro.prewalk(ast, [], &get_erlang_funs_of_type(&1, &2, type, :erlang))
    acc
  end

  def get_erlang_funs_of_type({{:., _, [module, type]}, _, _} = ast, acc, type, module) do
    {ast, [ast | acc]}
  end

  def get_erlang_funs_of_type({:&, _, [{:/, _, [{fun, meta, _}, idx]}]}, acc, type, module) do
    fun_cap = create_fun_cap(fun, meta, idx)
    get_erlang_funs_of_type(fun_cap, acc, type, module)
  end

  def get_erlang_funs_of_type(ast, acc, _type, _module), do: {ast, acc}

  def get_erlang_aliased_funs_of_type(ast, type, module) do
    {_, acc} = Macro.prewalk(ast, [], &get_erlang_funs_of_type(&1, &2, type, module))
    acc
  end

  def get_piped_erlang_aliased_funs_of_type(ast, type, module) do
    case ast do
      {{:., _, [^module, ^type]}, _, _} ->
        [ast]

      _ ->
        []
    end
  end

  def get_funs_by_module(ast, module) do
    {_, acc} = Macro.prewalk(ast, [], &contains_module(&1, &2, module))
    acc
  end

  def get_assigns_from(fun, module) when is_list(module) do
    get_funs_of_type(fun, :=)
    |> Enum.filter(&contains_module?(&1, module))
    |> Enum.map(&get_assign/1)
  end

  defp contains_module?(ast, module) do
    {_, acc} = Macro.prewalk(ast, [], &contains_module(&1, &2, module))
    if length(acc) > 0, do: true, else: false
  end

  defp contains_module({{:., _, [{:__aliases__, _, module}, _]}, _, _} = ast, acc, module) do
    {module, [ast | acc]}
  end

  defp contains_module(ast, acc, _), do: {ast, acc}

  defp get_assign({_, _, [{val, _, _} | _]}), do: val
  defp get_assign(_), do: ""

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

  def get_strict_aliased_funs_of_type(
        {{:., _, [{:__aliases__, _, aliases}, type]}, _, _opts} = ast,
        acc,
        type,
        module
      ) do
    if aliases === module do
      {ast, [ast | acc]}
    else
      {ast, acc}
    end
  end

  def get_strict_aliased_funs_of_type(
        {:&, _, [{:/, _, [{fun, meta, _}, idx]}]},
        acc,
        type,
        module
      ) do
    fun_cap = create_fun_cap(fun, meta, idx)
    get_strict_aliased_funs_of_type(fun_cap, acc, type, module)
  end

  def get_strict_aliased_funs_of_type(ast, acc, _type, _module) do
    {ast, acc}
  end

  def get_aliased_funs_of_type(
        {{:., _, [{:__aliases__, _, aliases}, type]}, _, _opts} = ast,
        acc,
        type,
        module
      ) do
    if List.last(aliases) === module do
      {ast, [ast | acc]}
    else
      {ast, acc}
    end
  end

  def get_aliased_funs_of_type({:&, _, [{:/, _, [{fun, meta, _}, idx]}]}, acc, type, module) do
    fun_cap = create_fun_cap(fun, meta, idx)
    get_aliased_funs_of_type(fun_cap, acc, type, module)
  end

  def get_aliased_funs_of_type(ast, acc, _type, _module) do
    {ast, acc}
  end

  def get_piped_aliased_funs_of_type(ast, type, module) when is_list(module) do
    case ast do
      {{:., _, [{:__aliases__, _, ^module}, ^type]}, _, _} ->
        [ast]

      _ ->
        []
    end
  end

  def get_piped_aliased_funs_of_type(ast, type, module) do
    case ast do
      {{:., _, [{:__aliases__, _, aliases}, ^type]}, _, _} ->
        if List.last(aliases) === module do
          [ast]
        else
          []
        end

      _ ->
        []
    end
  end

  def get_top_level_funs_of_type(ast, type) do
    {_, acc} = Macro.prewalk(ast, [], &get_top_level_funs_of_type(&1, &2, type))
    acc
  end

  def get_top_level_funs_of_type({:&, _, [{:/, _, [{fun, meta, _}, idx]}]}, acc, type) do
    fun_cap = create_fun_cap(fun, meta, idx)
    get_top_level_funs_of_type(fun_cap, acc, type)
  end

  def get_top_level_funs_of_type({type, _, _} = ast, acc, type) do
    {[], [ast | acc]}
  end

  def get_top_level_funs_of_type(ast, acc, _type) do
    {ast, acc}
  end

  def get_funs_of_type(ast, type) do
    {_, acc} = Macro.prewalk(ast, [], &get_funs_of_type(&1, &2, type))
    acc
  end

  # This should not effect piped, aliased, etc get_funs* functions.
  def get_funs_of_type({name, _, opts}, acc, type) when name in [:def, :defp, :defmacro] do
    case Macro.prewalk(opts, [], &get_do_block/2) do
      {_, [[{:do, block}]]} ->
        get_funs_of_type(block, acc, type)

      _ ->
        {[], acc}
    end
  end

  def get_funs_of_type({type, _, _} = ast, acc, types) when is_list(types) do
    if Enum.member?(types, type) do
      {ast, [ast | acc]}
    else
      {ast, acc}
    end
  end

  def get_funs_of_type({:&, _, [{:/, _, [{fun, meta, _}, idx]}]}, acc, type) do
    fun_cap = create_fun_cap(fun, meta, idx)
    get_funs_of_type(fun_cap, acc, type)
  end

  def get_funs_of_type({type, _, _} = ast, acc, type) do
    {ast, [ast | acc]}
  end

  def get_funs_of_type(ast, acc, _type), do: {ast, acc}

  def get_piped_funs_of_type(ast, type) do
    case ast do
      {^type, _, _} ->
        [ast]

      _ ->
        []
    end
  end

  defp create_fun_cap(fun, meta, idx) when is_number(idx) do
    opts = Enum.map(1..idx, fn i -> {:&, [], [i]} end)
    {fun, meta, opts}
  end

  defp create_fun_cap(fun, meta, _) do
    {fun, meta, [{:&, [], []}]}
  end

  def get_pipe_funs(ast) do
    all_pipes = get_funs_of_type(ast, :|>)

    Enum.filter(all_pipes, fn pipe ->
      {_, acc} = Macro.prewalk(pipe, [], &get_do_block/2)
      Enum.empty?(acc)
    end)
  end

  def get_do_block({:|>, _, [_, {_, _, [[do: _block]]}]} = ast, acc) do
    {[], [ast | acc]}
  end

  def get_do_block([do: _block] = ast, acc), do: {[], [ast | acc]}
  def get_do_block(ast, acc), do: {ast, acc}

  def extract_opts({:send_resp, _, nil}), do: []
  def extract_opts({:send_resp, _, opts}), do: parse_opts(List.last(opts))

  def extract_opts({{:., _, _}, _, _opts} = fun) do
    parse_opts(fun)
  end

  def extract_opts({:<<>>, _, opts}) do
    opts
    |> Enum.map(&parse_string_interpolation/1)
  end

  def extract_opts({val, _, nil}), do: [val]
  def extract_opts({val, _, []}), do: [val]

  def extract_opts({_, _, opts}) when is_list(opts) do
    opts
    |> Enum.map(&parse_opts/1)
  end

  def extract_opts(opts) when is_list(opts), do: Enum.map(opts, &parse_opts/1)
  def extract_opts(_), do: []
  # A more general extract_opts. May be able to replace some of the
  # function specific extractions.
  def extract_opts({_, _, nil}, _idx), do: []

  def extract_opts({_, _, opts}, idx) do
    parse_opts(Enum.at(opts, idx))
  end

  defp parse_opts({:@, _, _}), do: []
  defp parse_opts({key, _, nil}), do: key

  defp parse_opts({:<<>>, _, opts}) do
    Enum.map(opts, &parse_string_interpolation/1)
    |> List.flatten()
  end

  defp parse_opts({{:., _, [Access, :get]}, _, [{{:., _, [{:conn, _, nil}, :params]}, _, _}, _]}) do
    "conn.params"
  end

  defp parse_opts({{:., _, [Access, :get]}, _, opts}) do
    [{val, _, _} | _] = opts
    val
  end

  defp parse_opts({{:., _, _}, _, [{:var!, _, [{:assigns, _, EEx.Engine}]}, var]}) do
    "@#{var}"
  end

  defp parse_opts({{:., _, [{:__aliases__, _, module}, _func]}, _, _}) do
    Module.concat(module)
  end

  # This is what an accessor func looks like, eg conn.params
  defp parse_opts({{:., _, [{val, _, nil}, _]}, _, _}), do: val
  defp parse_opts({:., _, [{val, _, nil}, _]}), do: val

  defp parse_opts({{:., _, opts}, _, _} = _fun) do
    parse_opts(opts)
  end

  defp parse_opts({:&, _, [i]} = cap) when is_integer(i), do: Macro.to_string(cap)

  defp parse_opts({fun, _, opts}) when fun in @operators do
    Enum.map(opts, &parse_opts/1)
  end

  # Sigils aren't ordinary function calls.
  defp parse_opts({fun, _, _}) when fun in [:sigil_s, :sigil_e], do: []
  defp parse_opts({fun, _, opts}) when is_list(opts), do: fun
  defp parse_opts(opts) when is_tuple(opts), do: parse_opts(Tuple.to_list(opts))
  defp parse_opts(opts) when is_list(opts), do: Enum.map(opts, &parse_opts/1)
  defp parse_opts(_), do: []

  def get_fun_declaration({_, _, fun_opts}) do
    [definition | _] = fun_opts

    declaration =
      case definition do
        {:when, _, [opts | _]} -> opts
        opts -> opts
      end

    params = get_params(declaration)
    {fun_name, _, _} = declaration

    {params, {fun_name, get_fun_line(declaration)}}
  end

  def get_fun_declaration(_) do
    {[], {"", ""}}
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

  def get_pipe_val(ast, pipe_fun) do
    {_, acc} = Macro.prewalk(ast, [], &get_pipe_val(&1, &2, pipe_fun))
    acc
  end

  def get_pipe_val({:|>, _, [{:|>, _, opts}, pipefun]}, acc, pipefun) do
    key = extract_opts(List.last(opts))
    {[], [key | acc]}
  end

  def get_pipe_val({:|>, _, [opts, pipefun]}, acc, pipefun) do
    key = extract_opts(opts)
    {[], [key | acc]}
  end

  def get_pipe_val({:|>, _, [{fun, _, funopts} = opts, maybe_pipe]} = ast, acc, pipe)
      when not (fun in [:|>]) do
    {_, match_pipe} = Macro.prewalk(maybe_pipe, [], &get_match(&1, &2, pipe))
    {_, match_opts} = Macro.prewalk(opts, [], &get_match(&1, &2, pipe))

    cond do
      !Enum.empty?(match_pipe) ->
        {maybe_pipe, acc}

      !Enum.empty?(match_opts) ->
        key = extract_opts(funopts)
        {[], [key | acc]}

      true ->
        {ast, acc}
    end
  end

  def get_pipe_val(ast, acc, _pipe), do: {ast, acc}

  defp get_match(match, acc, match), do: {[], [match | acc]}
  defp get_match(ast, acc, _), do: {ast, acc}

  defp parse_string_interpolation({key, _, nil}), do: key

  defp parse_string_interpolation({:"::", _, opts}) do
    parse_string_interpolation(opts)
  end

  defp parse_string_interpolation([{{:., _, [Kernel, :to_string]}, _, vars}, _]) do
    Enum.map(vars, &parse_opts/1)
  end

  defp parse_string_interpolation({{:., _, [Kernel, :to_string]}, _, opts}) do
    Enum.map(opts, &parse_opts/1)
  end

  defp parse_string_interpolation({:<<>>, _, opts}) do
    opts
    |> Enum.map(&parse_string_interpolation/1)
  end

  defp parse_string_interpolation(_) do
    []
  end

  def get_fun_line({_, meta, _}) when is_list(meta) do
    Keyword.get(meta, :line, 0)
  end

  def get_fun_column({_, meta, _}) when is_list(meta) do
    Keyword.get(meta, :column, 0)
  end

  # XSS Utils

  def get_template_vars(raw_funs) do
    Enum.flat_map(raw_funs, fn ast ->
      {vars, _, _} = get_fun_vars_and_meta([ast], 0, :raw, :HTML)

      Enum.flat_map(vars, fn {_, var} ->
        var
      end)
    end)
  end

  def parse_render_opts({:render, _, opts}, params, idx) do
    {_, vars} = Macro.prewalk(opts, [], &extract_render_opts/2)

    template = if is_nil(opts) || Enum.empty?(opts), do: "", else: Enum.at(opts, idx)

    reflected_vars =
      Enum.filter(vars, fn var ->
        (is_reflected_var?(var) && is_in_params?(var, params)) || is_conn_params?(var)
      end)

    var_keys =
      Enum.map(vars, fn {key, val} ->
        case val do
          {_, _, _} -> key
          _ -> nil
        end
      end)

    reflected_var_keys = Keyword.keys(reflected_vars)

    {template, reflected_var_keys, var_keys -- reflected_var_keys}
  end

  def extract_render_opts(ast, acc) do
    if Keyword.keyword?(ast) do
      {ast, ast}
    else
      {ast, acc}
    end
  end

  defp is_reflected_var?({_, {_, _, nil}}), do: true
  defp is_reflected_var?(_), do: false

  defp is_in_params?({_, {var, _, _}}, params) do
    Enum.member?(params, var)
  end

  def is_conn_params?({_, {{:., _, [Access, :get]}, _, access_opts}}),
    do: is_conn_params?(access_opts)

  def is_conn_params?([{{:., _, [{:conn, _, nil}, :params]}, _, []}, _]), do: true
  def is_conn_params?(_), do: false
end
