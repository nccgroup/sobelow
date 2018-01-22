defmodule GoodRouter do
  pipeline :browser do
    plug(:accepts, ["html"])
    plug(:put_secure_browser_headers)
  end
end
