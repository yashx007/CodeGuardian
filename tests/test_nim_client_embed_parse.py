import json
from unittest.mock import patch, MagicMock

from agent.nim_client import NIMClient


def test_parse_integrate_v1_embedding_shape(monkeypatch):
    client = NIMClient(inference_url=None, embedding_url="https://example.com/v1/embeddings", api_key="fake")

    # mock requests.post
    fake_response = MagicMock()
    fake_response.raise_for_status.return_value = None
    fake_response.json.return_value = {
        "object": "list",
        "data": [{"index": 0, "embedding": [0.1, 0.2, 0.3]}],
    }

    with patch("agent.nim_client.requests.post", return_value=fake_response) as mock_post:
        embs = client.embed(["hello world"])  # should parse integrate v1 shape
        assert isinstance(embs, list)
        assert embs[0] == [0.1, 0.2, 0.3]
        # ensure we called the URL
        mock_post.assert_called()


def test_parse_legacy_embedding_shape(monkeypatch):
    client = NIMClient(inference_url=None, embedding_url="https://example.com/v1/embeddings", api_key="fake")
    fake_response = MagicMock()
    fake_response.raise_for_status.return_value = None
    fake_response.json.return_value = {"embeddings": [[0.4, 0.5]]}

    with patch("agent.nim_client.requests.post", return_value=fake_response) as mock_post:
        embs = client.embed(["hi"])
        assert embs == [[0.4, 0.5]]
        mock_post.assert_called()
