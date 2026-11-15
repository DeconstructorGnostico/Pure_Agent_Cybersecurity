"""Utilities shared by the specialty tests."""
import shutil
import tempfile
from pathlib import Path

from pure_agent_cyber import PureAgentCyber


class WithAgent:
    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp(prefix="apc_test_"))
        self.ag = PureAgentCyber(secret=b"pruebas", sandbox=self._tmp)

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def dec(self, text, document=None, session=None):
        return self.ag.evaluate(text, document=document, session=session or text[:20]).decision.value
