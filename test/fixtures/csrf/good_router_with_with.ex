defmodule GoodRouterWithWith do
  pipeline :browser do
    plug(:accepts, ["html"])
    plug(:protect_from_forgery, with: :clear_session)
  end
end
