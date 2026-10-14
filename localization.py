"""Presentation-only translations. Vault fields and user data are never translated."""
import json
from pathlib import Path
import sys
LANGUAGE='ru'
CATALOG=json.loads((Path(getattr(sys,'_MEIPASS',Path(__file__).parent))/'translations.json').read_text(encoding='utf8'))
def set_language(language):
    global LANGUAGE
    LANGUAGE='en' if language=='en' else 'ru'
def install():
    pass
def tr(text):
    if LANGUAGE!='en' or not isinstance(text,str):return text
    if text in CATALOG:return CATALOG[text]
    # Leading whitespace in sidebar labels and formatted messages is significant.
    stripped=text.strip()
    if stripped in CATALOG:
        start=len(text)-len(text.lstrip());end=len(text.rstrip())
        return text[:start]+CATALOG[stripped]+text[end:]
    return text
