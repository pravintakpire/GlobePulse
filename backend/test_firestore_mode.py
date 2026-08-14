import os
import sys
import unittest
from unittest.mock import patch

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import config


class TestFirestoreEmulatorHostDefault(unittest.TestCase):
    """backend/config.py must not force emulator mode by default -- that's
    what blocked cloud mode from ever being reachable before this change."""

    def test_defaults_to_none_when_unset(self):
        env_patcher = patch.dict(os.environ)
        env_patcher.start()
        self.addCleanup(env_patcher.stop)
        os.environ.pop("FIRESTORE_EMULATOR_HOST", None)

        settings = config.Settings(_env_file=None)

        self.assertIsNone(settings.firestore_emulator_host)


if __name__ == "__main__":
    unittest.main()
