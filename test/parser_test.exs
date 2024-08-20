defmodule SobelowTest.ParserTest do
  use ExUnit.Case
  import ExUnit.CaptureIO
  alias Sobelow.RCE.CodeModule
  alias Sobelow.Parse

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
      CodeModule.run(ast, @metafile)
    end

    assert capture_io(run_test) =~ "Code Execution in `Code.eval_string` - Medium Confidence"
  end

  test "Remainder of line after sobelow_skip expression is ignored" do
    Sobelow.put_env(:skip, true)
    file = "./test/fixtures/parser/parse_skip.ex"

    %{def_funs: defs} = Parse.ast(file)
                        |> Parse.get_meta_funs()
    assert not Enum.empty?(defs)
  after
    Sobelow.put_env(:skip, false)
   end 
end
