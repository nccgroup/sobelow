defmodule GoodRouterWithSessionKey do
  pipeline :browser do
    plug :accepts, ["html"]
    plug :protect_from_forgery, session_key: "_phoenix_csrf_token"
  end
end
