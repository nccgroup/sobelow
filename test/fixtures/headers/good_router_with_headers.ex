defmodule GoodRouter do
  @moduledoc false

  pipeline :browser do
    plug(:accepts, ["html"])
    plug(:put_secure_browser_headers, %{"additional" => "header"})
  end
end
