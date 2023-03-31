defmodule GoodRouter do
  @moduledoc false

  pipeline :browser do
    plug(:accepts, ["html"])
    plug(:put_secure_browser_headers, %{"content-security-policy" => "default-src 'self'"})
  end
end
