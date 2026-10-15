"""Regression checks for the visual system without launching a GUI."""
import unittest
import moi_paroli as app


class ThemeContractTests(unittest.TestCase):
    def test_all_themes_have_same_semantic_colors(self):
        self.assertEqual(set(app.DARK), set(app.LIGHT))
        self.assertGreaterEqual(len(app.DARK), 12)

    def test_all_colors_are_hex(self):
        for theme in app.THEMES.values():
            for name, color in theme.items():
                with self.subTest(color=name):
                    self.assertRegex(color, r'^#[0-9a-fA-F]{6}$')

    def test_dark_has_readable_contrast(self):
        def lum(s):
            values = [int(s[i:i+2], 16) / 255 for i in (1, 3, 5)]
            rgb = [v / 12.92 if v <= .04045 else ((v+.055)/1.055)**2.4 for v in values]
            return sum(v*w for v,w in zip(rgb, (.2126,.7152,.0722)))
        for foreground, background in [('fg','panel'),('muted','panel'),('accent_fg','accent')]:
            fg, bg = map(lambda c: lum(app.DARK[c]), (foreground, background))
            ratio = (max(fg,bg)+.05)/(min(fg,bg)+.05)
            with self.subTest(pair=(foreground,background)):
                self.assertGreaterEqual(ratio, 4.5)

    def test_unchanged_vault_version(self):
        self.assertEqual(app.APP_VERSION, '4.6.1')

