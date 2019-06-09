defmodule PhoenixWeb.Endpoint do
  use Phoenix.Endpoint, otp_app: :phoenix

  socket("/socket", PhoenixInternalsWeb.UserSocket, websocket: true, longpoll: false)
end
