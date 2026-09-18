import tempfile
from attnndef.context import ContextStore, OperatorContext

def test_context_round_trip():
    with tempfile.TemporaryDirectory() as d:
        store = ContextStore(f"{d}/state.db")
        assert store.load() is None
        saved = store.save(OperatorContext(operator_name="Kai", profile="Competition", current_round=3))
        loaded = store.load()
        assert loaded.operator_name == "Kai"
        assert loaded.profile == "Competition"
        assert loaded.current_round == 3
        assert loaded.session_id == saved.session_id
