from typing import Any, Dict
import json

def format_json_output(data: Dict[str, Any]) -> str:
    """
    Format dictionary data as pretty-printed JSON.
    """
    return json.dumps(data, indent=2, sort_keys=True)
