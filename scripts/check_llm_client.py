import argparse
import json
from src.integrations import llm_client
from src.analysis.auto_llm import _resolve_prompt_version


def main() -> None:
    parser = argparse.ArgumentParser(description='Inspect the default LLM client wiring.')
    parser.add_argument('--prompt-versions', action='store_true', help='Include Tier1/Tier2 prompt version hashes.')
    args = parser.parse_args()

    c = llm_client.DEFAULT_CLIENT
    info = {
        'type': type(c).__name__,
        'provider': getattr(c, 'provider', None),
        'mock': getattr(c, 'mock', None) if hasattr(c, 'mock') else None,
        'ollama_enabled': getattr(c, 'ollama_enabled', None) if hasattr(c, 'ollama_enabled') else None,
        'ollama_host': getattr(c, 'ollama_host', None) if hasattr(c, 'ollama_host') else None,
    }
    if args.prompt_versions:
        info['prompt_versions'] = {
            'tier1': _resolve_prompt_version('tier1'),
            'tier2': _resolve_prompt_version('tier2'),
        }
    print(json.dumps(info, indent=2))


if __name__ == '__main__':
    main()
