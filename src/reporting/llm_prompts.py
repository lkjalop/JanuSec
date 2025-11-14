import json

SUMMARY_PROMPT_TEMPLATE = '''
You are a security analyst assistant. Produce a JSON object with keys: company_name (optional), recipients (array), key_findings (array of short strings), one_line_recommendation (string), and provenance (object).
Input Summary: {summary}
Top rows count: {row_count}
Return only the JSON object. Keep items concise.
'''


def build_summary_prompt(summary, row_count):
    try:
        s = summary or {}
        return SUMMARY_PROMPT_TEMPLATE.format(summary=json.dumps(s), row_count=int(row_count or 0))
    except Exception:
        return SUMMARY_PROMPT_TEMPLATE.format(summary=str(summary), row_count=int(row_count or 0))


def parse_structured_summary(text):
    # Try to extract a JSON object from text
    try:
        # Attempt direct parse
        j = json.loads(text)
        return j
    except Exception:
        # Fallback: find first '{' and last '}' and try to parse substring
        try:
            start = text.find('{')
            end = text.rfind('}')
            if start != -1 and end != -1 and end > start:
                sub = text[start:end+1]
                return json.loads(sub)
        except Exception:
            pass
    # As a last resort return text wrapped
    return {'text': text}
