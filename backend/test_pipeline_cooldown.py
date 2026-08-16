import os
import sys
import time
import unittest
from unittest.mock import patch

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
# Also add the repo root (parent of backend/) so that main.py's own
# `from backend.agents.orchestrator import ...` can resolve `backend` as a
# top-level (namespace) package -- it isn't on sys.path by default when
# these tests are invoked from within backend/ (e.g. `cd backend && python3
# -m unittest test_pipeline_cooldown`). Same fix as test_pipeline_agents.py.
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import main


class TestPipelineCooldown(unittest.TestCase):
    def setUp(self):
        main._last_ticker_run.clear()

    def test_first_call_for_a_ticker_is_not_gated(self):
        self.assertNotIn("TSLA", main._last_ticker_run)
        # Directly exercises the same lookup trigger_pipeline() does.
        now = time.time()
        last_run = main._last_ticker_run.get("TSLA")
        gated = last_run is not None and (now - last_run) < main._PIPELINE_COOLDOWN_SECONDS
        self.assertFalse(gated)

    def test_second_call_within_window_is_gated(self):
        main._last_ticker_run["TSLA"] = time.time()
        now = time.time()
        last_run = main._last_ticker_run.get("TSLA")
        gated = last_run is not None and (now - last_run) < main._PIPELINE_COOLDOWN_SECONDS
        self.assertTrue(gated)

    def test_call_after_window_passes(self):
        main._last_ticker_run["TSLA"] = time.time() - main._PIPELINE_COOLDOWN_SECONDS - 1
        now = time.time()
        last_run = main._last_ticker_run.get("TSLA")
        gated = last_run is not None and (now - last_run) < main._PIPELINE_COOLDOWN_SECONDS
        self.assertFalse(gated)


if __name__ == "__main__":
    unittest.main()
