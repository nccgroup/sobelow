defmodule Sobelow do
  @moduledoc """
  Documentation for Sobelow.
  """

  @doc """
  Hello world.

  ## Examples

      iex> Sobelow.hello
      :world

  """
  alias Sobelow.Utilsx, as: Utils
  alias Sobelow.Config
  alias Sobelow.XSS
  alias Sobelow.SQL
  alias Sobelow.Traversal
  alias Mix.Shell.IO

  def run(opts) do
    project_root = Keyword.get(opts, :root, ".") <> "/"
    app_name = Utils.get_app_name(project_root <> "mix.exs")
    web_root = get_root(app_name, project_root)

    root = if String.ends_with?(web_root, "./"), do: web_root <> "web/", else: web_root

    if !File.exists?(web_root <> "web/router.ex") do
      IO.error("This does not appear to be a Phoenix application.")
      System.halt(0)
    end

    Config.fetch(web_root)
    Utils.all_files(root)
    |> Enum.reject(&is_nil/1)
    |> Enum.each(fn file ->
        def_funs = Utils.get_def_funs(root <> file)
        |> Enum.each(&get_fun_vulns(&1, file, web_root <> "web/"))
    end)
  end

  defp get_root(app_name, project_root) do
    if File.exists?(project_root <> "lib/#{String.downcase(app_name)}/web/router.ex") do
      project_root <> "lib/#{String.downcase(app_name)}/"
    else
      project_root <> "./"
    end
  end

  def get_fun_vulns(fun, filename, web_root) do
    if String.ends_with?(filename, "_controller.ex") do
      XSS.get_vulns(fun, filename, web_root)
    end
    SQL.get_vulns(fun, filename)
    Traversal.get_vulns(fun, filename)
  end
end
