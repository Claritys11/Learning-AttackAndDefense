import tempfile
from attnndef.context import ContextStore
from attnndef.ui import InteractiveConsole

def test_console_configures_and_exits():
    with tempfile.TemporaryDirectory() as d:
        answers = iter(["1", "Kai", "Team", "T1", "", "", "", "", "", "", "", "0"])
        output = []
        console = InteractiveConsole(ContextStore(f"{d}/state.db"), lambda _prompt: next(answers), output.append)
        assert console.run() == 0
        assert console.store.load().operator_name == "Kai"
        assert any("MAIN MENU" in line for line in output)
