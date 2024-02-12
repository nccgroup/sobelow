defmodule SobelowTest.PrintTest do
  use ExUnit.Case
  import ExUnit.CaptureIO
  alias Sobelow.RCE.CodeModule

  @metafile %{filename: "test.ex", controller?: true}

  setup do
    Application.put_env(:sobelow, :format, "txt")
    Sobelow.Fingerprint.start_link()

    :ok
  end

  test "Prints variables with map access" do
    func = """
    def call(conn, _opts) do
      Code.eval_string(conn.body_params["code"])
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    run_test = fn ->
      CodeModule.run(ast, @metafile)
    end

    assert capture_io(run_test) =~ "Code Execution in `Code.eval_string` - Medium Confidence"
  end
end
