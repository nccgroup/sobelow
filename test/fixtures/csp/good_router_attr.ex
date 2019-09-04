defmodule GoodRouter do
  @csp %{"content-security-policy" => "default-src 'self'"}

  pipeline :browser do
    plug(:accepts, ["html"])
    plug(:put_secure_browser_headers, @csp)
  end
end
