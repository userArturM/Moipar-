"""English presentation coverage; vault contents are never translated."""
import ast
import re
import unittest
from pathlib import Path
import localization as loc
import moi_paroli as app


class EnglishTests(unittest.TestCase):
    def setUp(self):
        self.addCleanup(loc.set_language, loc.LANGUAGE)
        loc.set_language('en')

    def test_literal_messages_have_translations(self):
        missing = []
        for path in Path(app.__file__).parent.glob('*.py'):
            for node in ast.walk(ast.parse(path.read_text(encoding='utf8'))):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'tr' and node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                    value = node.args[0].value
                    if value != 'Русский' and re.search('[А-Яа-яЁё]', loc.tr(value)):
                        missing.append((path.name, node.lineno, value))
        self.assertEqual(missing, [])

    def test_template_labels(self):
        for name, template in app.TEMPLATES.items():
            labels = [name, template.get('category', '')]
            labels += [field[0] if isinstance(field, (list, tuple)) else field for field in template.get('fields', [])]
            for label in labels:
                self.assertNotRegex(loc.tr(label), '[А-Яа-яЁё]')

    def test_user_content_and_whitespace(self):
        self.assertEqual(loc.tr('  Избранное  '), '  Favorites  ')
        self.assertEqual(loc.tr('Личный аккаунт Ивана'), 'Личный аккаунт Ивана')
        self.assertTrue(loc.tr('Не удалось сохранить данные:\n').endswith('\n'))
