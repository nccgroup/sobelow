defmodule Sobelow.SQL do
  alias Sobelow.SQL.Inject
  @submodules [Sobelow.SQL.Inject]

  def get_vulns(fun, filename, _web_root) do
    filename = String.replace_prefix(filename, "/", "")
    allowed = @submodules -- Sobelow.get_ignored()

    Enum.each allowed, fn mod ->
      apply(mod, :run, [fun, filename])
    end
  end
end