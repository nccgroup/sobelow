defmodule BadRouter do
  pipeline :browser do
    plug(:accepts, ["html"])
    plug(:protect_from_forgery)
  end

  def pipeline(config, pipeline_opts) do
    config
    |> Map.fetch!(:schema_mod)
    |> Pipeline.for_document(pipeline_opts)
    |> Pipeline.insert_after(Resolution, ObjectScopeAuthorization)
  end
end
