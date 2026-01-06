defmodule SobelowTest.ParserTest do
  use ExUnit.Case
  import ExUnit.CaptureIO
  alias Sobelow.RCE.CodeModule

  @metafile %{filename: "test.ex", controller?: true}

  setup do
    Application.put_env(:sobelow, :format, "txt")
    Sobelow.Fingerprint.start_link()

    :ok
  end

  test "Parser handles unquoted capture funcs" do
    func = """
    def call(list) do
      Enum.map(list, &Code.eval_string/unquote(length(list)))
    end
    """

    {_, ast} = Code.string_to_quoted(func)

    run_test = fn ->
      Sobelow.FindingLog.start_link()

      CodeModule.run(ast, @metafile)

      # Wait for FindingLog GenServer to process the message and emit the log output
      Sobelow.FindingLog.log()
    end

    assert capture_io(run_test) =~ "Code Execution in `Code.eval_string` - Medium Confidence"
  end
end
