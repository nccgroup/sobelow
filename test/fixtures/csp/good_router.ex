defmodule GoodRouter do
  pipeline :browser do
    plug(:accepts, ["html"])
    plug(:put_secure_browser_headers, %{"Content-Security-Policy" => "default-src 'self'"})
  end
end
