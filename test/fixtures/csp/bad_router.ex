defmodule BadRouter do
  @moduledoc false

  pipeline :browser do
    plug(:accepts, ["html"])
    plug(:put_secure_browser_headers)
  end
end
