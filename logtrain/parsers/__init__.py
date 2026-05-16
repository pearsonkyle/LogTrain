from logtrain.parsers.base import BaseParser
from logtrain.parsers.claude import ClaudeParser
from logtrain.parsers.opencode import OpenCodeParser
from logtrain.parsers.qwen import QwenParser

REGISTRY: dict[str, type[BaseParser]] = {
    "claude": ClaudeParser,
    "opencode": OpenCodeParser,
    "qwen": QwenParser,
}


def get_parser(source: str) -> BaseParser:
    if source not in REGISTRY:
        raise ValueError(f"Unknown parser: {source}. Available: {list(REGISTRY)}")
    return REGISTRY[source]()
