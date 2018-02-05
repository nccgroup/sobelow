defmodule Sobelow.Utils do
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
  # General Utils
  def ast(filepath) do
    {:ok, ast} = Code.string_to_quoted(read_file(filepath))
    ast
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

  def is_controller?(uses) do
    has_use_type?(uses, :controller)
  end

  def has_use_type?([{:use, _, [_, type]} | _], type), do: true
  def has_use_type?([_ | t], type), do: has_use_type?(t, type)
  def has_use_type?(_, _), do: false

  def normalize_path(filename) do
    filename
    |> Path.expand("")
    |> String.replace_prefix("/", "")
  end

  # This should be about as big as it gets, and is still fairly simple
  # to understand. If it gets much more convoluted, an alternate
  # solution should be explored.
  def print_code(fun, :highlight_all) do
    IO.puts("\n")
    IO.puts(IO.ANSI.light_magenta() <> Macro.to_string(fun) <> IO.ANSI.reset())
  end

  def print_code(fun, find) do
    acc = ""

    func_string =
      Macro.to_string(fun, fn ast, string ->
        s = print_highlighted(string, ast, find)
        acc <> s
      end)

    IO.puts("\n")
    IO.puts(func_string)
  end

  def print_file_path_code(fun, var) do
    acc = ""

    func_string =
      Macro.to_string(fun, fn ast, string ->
        s =
          case ast do
            {:=, _, [{^var, _, nil} | _]} ->
              maybe_highlight(string, ast, var)

            {{:., _, [{:__aliases__, _, [:Path]}, _]}, _, _} ->
              maybe_highlight(string, ast, var)

            {{:., _, [{:__aliases__, _, [:File]}, _]}, _, _} ->
              maybe_highlight(string, ast, var)

            _ ->
              if is_nil(string), do: "", else: string
          end

        acc <> s
      end)

    IO.puts("\n")
    IO.puts(func_string)
  end

  def print_highlighted(string, ast, find) do
    case find do
      ^ast ->
        IO.ANSI.light_magenta() <> string <> IO.ANSI.reset()

      _ ->
        if is_nil(string), do: "", else: string
    end
  end

  defp maybe_highlight(string, ast, var) do
    if is_fun_with_var?(ast, var) do
      IO.ANSI.light_magenta() <> string <> IO.ANSI.reset()
    else
      string
    end
  end

  def is_fun_with_var?(fun, var) do
    {_, acc} = Macro.prewalk(fun, [], &is_fun_var/2)
    if Enum.member?(acc, var), do: true, else: false
  end

  defp is_fun_var({:__aliases__, _, aliases} = ast, acc) do
    {ast, [Module.concat(aliases) | acc]}
  end

  defp is_fun_var({:render, _, [_, _, keylist]} = ast, acc) do
    {ast, Keyword.keys(keylist) ++ acc}
  end

  defp is_fun_var({:render, _, [_, keylist]} = ast, acc) when is_list(keylist) do
    {ast, Keyword.keys(keylist) ++ acc}
  end

  defp is_fun_var({:&, _, [idx]} = ast, acc), do: {ast, ["&#{idx}" | acc]}
  defp is_fun_var({var, _, _} = ast, acc), do: {ast, [var | acc]}
  defp is_fun_var(ast, acc), do: {ast, acc}

  def find_call({call, _, _} = ast, acc, call) do
    {ast, acc <> Macro.to_string(ast)}
  end

  def find_call(ast, acc, _call), do: {ast, acc <> Macro.to_string(ast)}

  def add_finding(line_no, filename, fun, fun_name, vars, severity, finding, type)
      when is_list(vars) do
    var = if length(vars) > 1, do: Enum.join(vars, " and "), else: hd(vars)
    add_finding(line_no, filename, fun, fun_name, var, severity, finding, type)
  end

  def add_finding(line_no, filename, fun, fun_name, var, severity, finding, type) do
    case Sobelow.format() do
      "json" ->
        log_json_finding(line_no, filename, fun_name, var, severity, type)

      "txt" ->
        Sobelow.log_finding(type, severity)
        print_finding_metadata(line_no, filename, fun, fun_name, var, severity, type, finding)

      "compact" ->
        log_compact_finding(type, filename, line_no, severity)

      _ ->
        Sobelow.log_finding(type, severity)
    end
  end

  def print_finding_metadata(line_no, filename, fun, fun_name, var, severity, type, finding) do
    IO.puts(finding_header(type, severity))
    IO.puts(finding_file_metadata(filename, fun_name, line_no))
    IO.puts(finding_variable(var))
    maybe_print_code(fun, finding)
    IO.puts(finding_break())
  end

  def print_custom_finding_metadata(fun, finding, severity, type, headers) do
    IO.puts(finding_header(type, severity))

    Enum.each(headers, fn header ->
      IO.puts(header)
    end)

    maybe_print_code(fun, finding)
    IO.puts(finding_break())
  end

  def log_compact_finding(type, filename, line_no, severity) do
    details = "#{type} - #{filename}:#{line_no}"
    Sobelow.log_finding(details, severity)

    print_compact_finding(details, severity)
  end

  def log_compact_finding(type, severity) do
    Sobelow.log_finding(type, severity)
    print_compact_finding(type, severity)
  end

  defp print_compact_finding(details, severity) do
    sev =
      case severity do
        :high -> IO.ANSI.red()
        :medium -> IO.ANSI.yellow()
        :low -> IO.ANSI.green()
      end

    IO.puts("#{sev}[+]#{IO.ANSI.reset()} #{details}")
  end

  def log_json_finding(line_no, filename, fun_name, var, severity, type) do
    # The function name may be a tuple in instances where meta-programming is used.
    fun_name = if is_tuple(fun_name), do: Macro.to_string(fun_name), else: fun_name

    finding = [
      type: type,
      file: filename,
      function: "#{fun_name}:#{line_no}",
      variable: var
    ]

    Sobelow.log_finding(finding, severity)
  end

  def finding_header(type, severity) do
    {color, confidence} = finding_confidence(severity)
    color <> type <> " - #{confidence} Confidence" <> IO.ANSI.reset()
  end

  def finding_file_metadata(filename, {:unquote, _, _} = fun_name, line_no) do
    finding_file_metadata(filename, Macro.to_string(fun_name), line_no)
  end

  def finding_file_metadata(filename, fun_name, line_no) do
    "File: #{filename} - #{fun_name}:#{line_no}"
  end

  def finding_variable(var) do
    "Variable: #{var}"
  end

  def finding_confidence(severity) do
    case severity do
      :high -> {IO.ANSI.red(), "High"}
      :medium -> {IO.ANSI.yellow(), "Medium"}
      :low -> {IO.ANSI.green(), "Low"}
    end
  end

  def finding_break() do
    "\n-----------------------------------------------\n"
  end

  def maybe_print_code(fun, finding) do
    if Sobelow.get_env(:verbose), do: print_code(fun, finding)
  end

  def maybe_print_file_path_code(fun, var) do
    if Sobelow.get_env(:verbose), do: print_file_path_code(fun, var)
  end

  def get_sev(params, var) do
    do_get_sev(params, var, :medium, :low)
  end

  def get_sev(params, vars, severity) when is_list(vars) do
    Enum.map(vars, &get_sev(params, &1, severity))
    |> get_highest_sev()
  end

  def get_sev(params, var, false) do
    do_get_sev(params, var, :high, :medium)
  end

  def get_sev(_params, _var, severity) do
    severity
  end

  defp do_get_sev(params, var, high, low) do
    params = ["conn.params" | params]

    case Enum.member?(params, var) do
      true -> high
      false -> low
    end
  end

  defp get_highest_sev(sevs) do
    cond do
      Enum.member?(sevs, :high) -> :high
      Enum.member?(sevs, :medium) -> :medium
      true -> :low
    end
  end

  ## Function parsing
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
    init_acc = %{raw: []}
    {_, acc} = Macro.prewalk(ast, init_acc, &get_meta_template_fun(&1, &2))
    acc
  end

  def get_meta_template_fun({:raw, _, _} = ast, acc) do
    {ast, Map.update!(acc, :raw, &[ast | &1])}
  end

  def get_meta_template_fun(ast, acc), do: {ast, acc}

  def get_fun_vars_and_meta(fun, idx, type, module \\ nil) do
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

  defp get_funs(fun, type, module) do
    get_aliased_funs_of_type(fun, type, module)
  end

  defp get_funs_from_pipe(fun, type, nil) do
    get_pipe_funs(fun)
    |> Enum.map(fn {_, _, opts} -> Enum.at(opts, 1) end)
    |> Enum.flat_map(&get_piped_funs_of_type(&1, type))
    |> Enum.uniq()
  end

  defp get_funs_from_pipe(fun, type, module) do
    get_pipe_funs(fun)
    |> Enum.map(fn {_, _, opts} -> Enum.at(opts, 1) end)
    |> Enum.flat_map(&get_piped_aliased_funs_of_type(&1, type, module))
    |> Enum.uniq()
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

  def get_funs_of_type(ast, type) do
    {_, acc} = Macro.prewalk(ast, [], &get_funs_of_type(&1, &2, type))
    acc
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

  defp create_fun_cap(fun, meta, idx) do
    opts = Enum.map(1..idx, fn i -> {:&, [], [i]} end)
    {fun, meta, opts}
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

  def get_fun_declaration(fun) do
    {_, _, fun_opts} = fun
    [definition | _] = fun_opts

    declaration =
      case definition do
        {:when, _, [opts | _]} -> opts
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
      when fun not in [:|>] do
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

  defp parse_string_interpolation({:::, _, opts}) do
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

  ## File listing
  ## In normal situations, this shouldn't fail. However,
  ## if there is a failure in path or app_name, it could
  ## lead to an issue here. In these situations, the scan
  ## will now proceed normally, but print an error message
  ## for the user.
  def all_files(filepath, _directory \\ "") do
    if File.dir?(filepath) do
      Path.wildcard(filepath <> "/**/*.ex")
      |> Enum.reject(&String.contains?(&1, "/mix/tasks/"))
    else
      IO.puts(:stderr, "WARNING: Could not read web directory.\n")
      []
    end
  end

  def template_files(filepath, _directory \\ "") do
    if File.dir?(filepath) do
      Path.wildcard(filepath <> "/**/*.html.eex")
    else
      []
    end
  end

  # Setup Utils
  def get_app_name(filepath) do
    if File.exists?(filepath) do
      ast = ast(filepath)
      {_, project_block} = Macro.prewalk(ast, [], &extract_project_block/2)
      {_, app_name} = Macro.prewalk(project_block, [], &extract_app_name/2)
      if is_atom(app_name), do: Atom.to_string(app_name), else: app_name
    end
  end

  defp extract_project_block({:def, _, [{:project, _, _}, [do: block]]} = ast, _) do
    {ast, block}
  end

  defp extract_project_block(ast, acc) do
    {ast, acc}
  end

  defp extract_app_name(ast, acc) do
    if Keyword.keyword?(ast) && Keyword.get(ast, :app) do
      {ast, Keyword.get(ast, :app)}
    else
      {ast, acc}
    end
  end

  # Config utils

  def get_pipelines(filepath) do
    ast = ast(filepath)
    {_, acc} = Macro.prewalk(ast, [], &get_funs_of_type(&1, &2, :pipeline))
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
    ast = ast(filepath)
    {_, acc} = Macro.prewalk(ast, [], &extract_fuzzy_configs(&1, &2, key))
    acc
  end

  def get_configs(key, filepath) do
    ast = ast(filepath)
    {_, acc} = Macro.prewalk(ast, [], &extract_configs(&1, &2, key))
    acc
  end

  defp extract_fuzzy_configs({:config, _, opts} = ast, acc, key) do
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

  defp extract_configs({:config, _, opts} = ast, acc, key) do
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
    ast = ast(filepath)
    {_, acc} = Macro.prewalk(ast, [], &get_version(&1, &2))
    acc
  end

  def get_version({:@, _, nil} = ast, acc), do: {ast, acc}
  def get_version({:@, _, [{:version, _, [vsn]}]}, _acc) when is_binary(vsn), do: {vsn, vsn}
  def get_version(ast, acc), do: {ast, acc}

  # XSS Utils

  def get_template_vars(raw_funs) do
    Enum.flat_map(raw_funs, fn ast ->
      {_, acc} = Macro.prewalk(ast, [], &extract_template_vars(&1, &2))
      acc
    end)
  end

  defp extract_template_vars({:raw, _, [{_, _, [_, raw]}]} = ast, acc) do
    {ast, [raw | acc]}
  end

  defp extract_template_vars(ast, acc), do: {ast, acc}

  def is_content_type_html({:put_resp_content_type, _, opts}) do
    Enum.filter(opts, &is_binary/1)
    |> Enum.any?(&String.contains?(&1, "html"))
  end

  def is_content_type_html({{_, _, [_, :put_resp_content_type]}, _, opts}) do
    Enum.filter(opts, &is_binary/1)
    |> Enum.any?(&String.contains?(&1, "html"))
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
