defmodule Sobelow.Utils do
  @moduledoc false

  alias Sobelow.Parse

  def is_controller?(uses) do
    has_use_type?(uses, :controller)
  end

  def is_router?(uses) do
    has_use_type?(uses, :router)
  end

  def is_endpoint?([{:use, _, [{_, _, [:Phoenix, :Endpoint]}, _]} | _]), do: true
  def is_endpoint?([_ | t]), do: is_endpoint?(t)
  def is_endpoint?(_), do: false

  def has_use_type?([{:use, _, [_, type]} | _], type), do: true
  def has_use_type?([_ | t], type), do: has_use_type?(t, type)
  def has_use_type?(_, _), do: false

  def normalize_path(filename) do
    filename
    |> Path.expand("")
    |> String.replace_prefix("/", "")
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
      warning = """
      WARNING: Web directory was not found in the expected location.
      This may be a result of non-standard directory structure, or use
      of an umbrella project. All files in the "lib" directory were
      scanned for vulnerabilities.
      """

      IO.puts(:stderr, warning)

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
      ast = Parse.ast(filepath)
      {_, project_block} = Macro.prewalk(ast, [], &extract_project_block/2)
      {_, app_name} = Macro.prewalk(project_block, [], &extract_app_name/2)
      binarize_app_name(app_name, ast)
    end
  end

  defp binarize_app_name(app_name, _) when is_binary(app_name), do: app_name
  defp binarize_app_name(app_name, _) when is_atom(app_name), do: Atom.to_string(app_name)

  defp binarize_app_name({:@, _, [{module_attribute, _, _}]}, ast) do
    ast
    |> Macro.prewalk([], fn
      {:@, _, [{^module_attribute, _, [name]}]}, [] ->
        {[], name}

      ast, acc ->
        {ast, acc}
    end)
    |> elem(1)
    |> binarize_app_name(ast)
  end

  defp binarize_app_name(app_name, _), do: app_name

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

  def get_root() do
    root = Sobelow.get_env(:root)
    if is_nil(root), do: "", else: root
  end
end
