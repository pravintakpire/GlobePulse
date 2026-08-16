import os
import sys
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
# Also add the repo root (parent of backend/) so that
# `patch("backend.agents.orchestrator....")` below can resolve `backend` as
# a top-level (namespace) package -- it isn't on sys.path by default when
# these tests are invoked from within backend/ (e.g. `cd backend && python3
# -m unittest test_pipeline_agents`), matching main.py's own
# `from backend.agents.orchestrator import ...` which only resolves because
# main.py is always launched with the repo root as cwd (see start.sh /
# Dockerfile).
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pipeline


class TestCleanArticleWithAgent(unittest.IsolatedAsyncioTestCase):
    async def test_returns_agent_cleaned_text_on_success(self):
        mock_agent = AsyncMock()
        mock_agent.__aenter__.return_value = mock_agent
        mock_agent.__aexit__.return_value = None

        async def fake_response_iter():
            for chunk in ["Cleaned ", "article ", "text."]:
                yield chunk

        mock_response = fake_response_iter()
        mock_agent.chat = AsyncMock(return_value=mock_response)

        mock_agent_class = MagicMock(return_value=mock_agent)
        mock_research_config = MagicMock()

        with patch("google.antigravity.Agent", mock_agent_class), \
             patch("backend.agents.orchestrator.research_agent_config", mock_research_config):
            result = await pipeline.clean_article_with_agent("raw scraped text here", "TSLA")

        self.assertEqual(result, "Cleaned article text.")
        mock_agent_class.assert_called_once_with(mock_research_config)

    async def test_falls_back_to_regex_clean_on_agent_failure(self):
        mock_agent_class = MagicMock(side_effect=RuntimeError("agent unavailable"))

        with patch("google.antigravity.Agent", mock_agent_class), \
             patch("backend.agents.orchestrator.research_agent_config", MagicMock()):
            result = await pipeline.clean_article_with_agent("raw   scraped\n\ntext", "TSLA")

        # Falls back to the original regex whitespace-clean, never raises.
        self.assertEqual(result, "raw scraped text")

    async def test_emits_fallback_activity_event_on_agent_failure(self):
        mock_agent_class = MagicMock(side_effect=RuntimeError("agent unavailable"))
        emitted_events = []

        async def fake_on_activity(event):
            emitted_events.append(event)

        with patch("google.antigravity.Agent", mock_agent_class), \
             patch("backend.agents.orchestrator.research_agent_config", MagicMock()):
            await pipeline.clean_article_with_agent("raw text", "TSLA", on_activity=fake_on_activity)

        self.assertEqual(len(emitted_events), 1)
        self.assertEqual(emitted_events[0]["status"], "fallback")
        self.assertEqual(emitted_events[0]["agent"], "ResearchAgent")
        self.assertEqual(emitted_events[0]["ticker"], "TSLA")

    async def test_no_error_when_on_activity_omitted_on_failure(self):
        """on_activity is optional -- must not raise when the caller doesn't pass one."""
        mock_agent_class = MagicMock(side_effect=RuntimeError("agent unavailable"))

        with patch("google.antigravity.Agent", mock_agent_class), \
             patch("backend.agents.orchestrator.research_agent_config", MagicMock()):
            result = await pipeline.clean_article_with_agent("raw text", "TSLA")

        self.assertEqual(result, "raw text")


class TestScoreSentimentWithAgent(unittest.IsolatedAsyncioTestCase):
    async def test_returns_parsed_dict_on_success(self):
        mock_agent = AsyncMock()
        mock_agent.__aenter__.return_value = mock_agent
        mock_agent.__aexit__.return_value = None

        async def fake_response_iter():
            yield '{"overall_sentiment": 0.6, "layoffs": null}'

        mock_agent.chat = AsyncMock(return_value=fake_response_iter())
        mock_agent_class = MagicMock(return_value=mock_agent)
        mock_sentiment_config = MagicMock()

        with patch("google.antigravity.Agent", mock_agent_class), \
             patch("backend.agents.orchestrator.sentiment_analyst_config", mock_sentiment_config):
            result = await pipeline.score_sentiment_with_agent("article text", "TSLA")

        self.assertEqual(result, {"overall_sentiment": 0.6, "layoffs": None})
        mock_agent_class.assert_called_once_with(mock_sentiment_config)

    async def test_returns_none_on_agent_failure(self):
        """Must return None, not a fallback dict -- triggers.py's watchdog
        depends on None to exclude a failed score from its average."""
        mock_agent_class = MagicMock(side_effect=RuntimeError("agent unavailable"))

        with patch("google.antigravity.Agent", mock_agent_class), \
             patch("backend.agents.orchestrator.sentiment_analyst_config", MagicMock()):
            result = await pipeline.score_sentiment_with_agent("article text", "TSLA")

        self.assertIsNone(result)

    async def test_emits_fallback_activity_event_on_agent_failure(self):
        mock_agent_class = MagicMock(side_effect=RuntimeError("agent unavailable"))
        emitted_events = []

        async def fake_on_activity(event):
            emitted_events.append(event)

        with patch("google.antigravity.Agent", mock_agent_class), \
             patch("backend.agents.orchestrator.sentiment_analyst_config", MagicMock()):
            await pipeline.score_sentiment_with_agent("article text", "TSLA", on_activity=fake_on_activity)

        self.assertEqual(len(emitted_events), 1)
        self.assertEqual(emitted_events[0]["status"], "fallback")
        self.assertEqual(emitted_events[0]["agent"], "SentimentAnalyst")

    async def test_returns_none_on_malformed_json(self):
        mock_agent = AsyncMock()
        mock_agent.__aenter__.return_value = mock_agent
        mock_agent.__aexit__.return_value = None

        async def fake_response_iter():
            yield "not valid json"

        mock_agent.chat = AsyncMock(return_value=fake_response_iter())
        mock_agent_class = MagicMock(return_value=mock_agent)

        with patch("google.antigravity.Agent", mock_agent_class), \
             patch("backend.agents.orchestrator.sentiment_analyst_config", MagicMock()):
            result = await pipeline.score_sentiment_with_agent("article text", "TSLA")

        self.assertIsNone(result)


class TestAnalyzeSentimentStillAlwaysSucceeds(unittest.IsolatedAsyncioTestCase):
    async def test_falls_back_to_neutral_default_when_agent_scoring_fails(self):
        """analyze_sentiment() must keep its own always-succeeds contract --
        run_pipeline depends on never getting None from this one."""
        with patch("pipeline.score_sentiment_with_agent", AsyncMock(return_value=None)):
            result_json_str = await pipeline.analyze_sentiment("some text", "TSLA")

        import json
        result = json.loads(result_json_str)
        self.assertEqual(result["overall_sentiment"], 0.0)
        self.assertIsNone(result["layoffs"])


if __name__ == "__main__":
    unittest.main()
