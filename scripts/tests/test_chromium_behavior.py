"""Live checks of the exact production JavaScript helpers, not full-path qualification.

Generic unittest discovery skips this suite without BROWSERD_TEST_CHROMIUM. Run
this file directly to require a configured, sandbox-enabled Chromium executable.
No remote websites, production services, or browserd gateway are involved.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import sys
import unittest


REPOSITORY = Path(__file__).resolve().parents[2]
OWNER_SOURCE = REPOSITORY / "crates/browserd-worker/src/chromium_owner.rs"
HELPERS = (
    "NODE_ACTIONABLE_POINT_FUNCTION",
    "NODE_FILL_FUNCTION",
    "NODE_SET_CHECKED_FUNCTION",
    "NODE_SELECT_FUNCTION",
)


def production_helpers() -> dict[str, str]:
    """Decode the exact Rust string literals; fail if their representation changes."""
    source = OWNER_SOURCE.read_text(encoding="utf-8")
    helpers = {}
    for name in HELPERS:
        match = re.search(
            rf'const {name}: &str = ("(?:[^"\\]|\\.)*");', source
        )
        if match is None:
            raise ValueError(f"production helper literal unavailable: {name}")
        helpers[name] = json.loads(match.group(1))
    return helpers


class ChromiumHelperBehavior(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        binary = os.environ.get("BROWSERD_TEST_CHROMIUM")
        if not binary:
            raise unittest.SkipTest("BROWSERD_TEST_CHROMIUM is unset")
        executable = Path(binary).resolve(strict=True)
        if not executable.is_file() or not os.access(executable, os.X_OK):
            raise ValueError("BROWSERD_TEST_CHROMIUM must be an executable file")
        from playwright.sync_api import sync_playwright

        cls.helpers = production_helpers()
        cls.playwright = sync_playwright().start()
        cls.addClassCleanup(cls.playwright.stop)
        cls.browser = cls.playwright.chromium.launch(
            executable_path=str(executable),
            channel="chromium",
            chromium_sandbox=True,
            headless=True,
            args=["--disable-features=BackForwardCache"],
        )
        cls.addClassCleanup(cls.browser.close)

    def setUp(self) -> None:
        self.context = self.browser.new_context(viewport={"width": 800, "height": 600})
        self.addCleanup(self.context.close)
        self.page = self.context.new_page()
        self.page.set_default_timeout(5000)

    def fixture(self, html: str) -> None:
        self.page.set_content(html)
        self.page.evaluate(
            """() => {
                window.inputEvents = [];
                for (const name of ['input', 'change'])
                    document.addEventListener(name, event =>
                        inputEvents.push([event.type, event.target.id]));
            }"""
        )

    def call(self, helper: str, selector: str, *arguments, frame=None):
        locator = (frame or self.page).locator(selector)
        return locator.evaluate(
            f"(element, args) => ({self.helpers[helper]}).apply(element, args)",
            list(arguments),
        )

    def test_offscreen_target_scrolls_and_pointer_hits_the_target(self) -> None:
        self.fixture(
            '<div style="height:1800px"></div>'
            '<button id="target" onclick="this.dataset.clicked=1">target</button>'
        )
        point = self.call("NODE_ACTIONABLE_POINT_FUNCTION", "#target")
        self.assertTrue(point["ok"])
        self.assertGreater(self.page.evaluate("scrollY"), 0)
        self.assertTrue(0 <= point["x"] < 800 and 0 <= point["y"] < 600)
        self.page.mouse.click(point["x"], point["y"])
        self.assertEqual(self.page.locator("#target").get_attribute("data-clicked"), "1")

    def test_occluded_target_and_zero_area_target_are_rejected(self) -> None:
        self.fixture(
            '<button id="target" style="position:absolute;left:30px;top:30px">target</button>'
            '<div style="position:fixed;inset:0;background:white;z-index:1"></div>'
            '<button id="hidden" style="display:none">hidden</button>'
        )
        for selector in ("#target", "#hidden"):
            with self.subTest(selector=selector):
                self.assertFalse(self.call("NODE_ACTIONABLE_POINT_FUNCTION", selector)["ok"])

    def test_descendant_hit_is_an_actionable_target(self) -> None:
        self.fixture('<button id="target"><span>nested text</span></button>')
        self.assertTrue(self.call("NODE_ACTIONABLE_POINT_FUNCTION", "#target")["ok"])

    def test_child_frame_points_require_translation_to_the_root_viewport(self) -> None:
        self.fixture('<iframe style="position:absolute;left:240px;top:150px;border:0"></iframe>')
        frame = self.page.frames[1]
        frame.set_content(
            '<button id="target" style="position:absolute;left:20px;top:25px;'
            'width:100px;height:40px" onclick="this.dataset.clicked=1">inside frame</button>'
        )
        point = self.call("NODE_ACTIONABLE_POINT_FUNCTION", "#target", frame=frame)
        self.assertTrue(point["ok"])
        self.assertAlmostEqual(point["x"], 70, delta=0.25)
        self.assertAlmostEqual(point["y"], 45, delta=0.25)
        iframe = self.page.locator("iframe")
        self.assertFalse(iframe.evaluate(
            "(element, point) => document.elementFromPoint(point.x, point.y) === element",
            point,
        ))
        root_box = iframe.bounding_box()
        self.assertIsNotNone(root_box)
        self.page.mouse.click(root_box["x"] + point["x"], root_box["y"] + point["y"])
        self.assertEqual(frame.locator("#target").get_attribute("data-clicked"), "1")

    def test_child_frame_nodes_are_rejected_in_a_foreign_execution_realm(self) -> None:
        self.fixture('<iframe style="position:absolute;left:240px;top:150px;border:0"></iframe>')
        frame = self.page.frames[1]
        frame.set_content('<div style="height:1800px"></div><button id="target">inside frame</button>')
        helper = self.helpers["NODE_ACTIONABLE_POINT_FUNCTION"]
        point = self.page.evaluate(
            f"() => ({helper}).call(document.querySelector('iframe').contentDocument.querySelector('#target'))"
        )
        self.assertFalse(point["ok"])
        self.assertEqual(frame.evaluate("scrollY"), 0)

    def test_paused_animation_has_stable_geometry_at_each_position(self) -> None:
        self.fixture('<button id="target">moving</button>')
        self.page.evaluate(
            """() => {
                window.motion = target.animate(
                    [{transform:'translateX(0px)'}, {transform:'translateX(200px)'}],
                    {duration:1000, fill:'both'});
                motion.pause(); motion.currentTime = 0;
            }"""
        )
        before = self.call("NODE_ACTIONABLE_POINT_FUNCTION", "#target")
        self.page.evaluate("motion.currentTime = 500")
        after = self.call("NODE_ACTIONABLE_POINT_FUNCTION", "#target")
        self.assertTrue(before["ok"] and after["ok"])
        self.assertAlmostEqual(after["x"] - before["x"], 100, delta=1)

    def test_running_animation_is_rejected_before_pointer_dispatch(self) -> None:
        self.fixture('<button id="target">moving</button>')
        self.page.evaluate("target.animate([{transform:'translateX(0)'},{transform:'translateX(400px)'}], {duration:500,iterations:Infinity,direction:'alternate'})")
        self.assertFalse(self.call("NODE_ACTIONABLE_POINT_FUNCTION", "#target")["ok"])

    def test_fill_rejects_disabled_readonly_and_wrong_element_kinds(self) -> None:
        for markup in (
            '<input id="target" disabled value="original">',
            '<textarea id="target" readonly>original</textarea>',
            '<input id="target" type="checkbox">',
            '<div id="target">original</div>',
        ):
            with self.subTest(markup=markup):
                self.fixture(markup)
                before = self.page.locator("#target").evaluate("el => el.outerHTML")
                self.assertFalse(self.call("NODE_FILL_FUNCTION", "#target", "한글 입력"))
                self.assertEqual(self.page.locator("#target").evaluate("el => el.outerHTML"), before)
                self.assertEqual(self.page.evaluate("inputEvents"), [])

    def test_fill_respects_disabled_fieldset_and_first_legend_exception(self) -> None:
        for tag in ("input", "textarea"):
            with self.subTest(tag=tag):
                self.fixture(
                    '<fieldset disabled><legend><input id="allowed"></legend>'
                    f'<{tag} id="target"></{tag}></fieldset>'
                )
                self.assertFalse(self.call("NODE_FILL_FUNCTION", "#target", "차단"))
                self.assertEqual(self.page.locator("#target").input_value(), "")
                self.assertEqual(self.page.evaluate("inputEvents"), [])
                self.assertTrue(self.call("NODE_FILL_FUNCTION", "#allowed", "허용"))
                self.assertEqual(self.page.locator("#allowed").input_value(), "허용")

    def test_native_value_setter_reaches_controlled_input_listener(self) -> None:
        self.fixture('<input id="target" value="before">')
        self.page.evaluate(
            """() => {
                const native = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value');
                window.tracked = target.value;
                window.observed = null;
                Object.defineProperty(target, 'value', {
                    get() { return native.get.call(this); },
                    set(value) { tracked = value; native.set.call(this, value); }
                });
                target.addEventListener('input', () => {
                    if (target.value !== tracked) observed = target.value;
                });
            }"""
        )
        self.assertTrue(self.call("NODE_FILL_FUNCTION", "#target", "한글 테스트"))
        self.assertEqual(self.page.evaluate("observed"), "한글 테스트")
        self.assertEqual(self.page.evaluate("inputEvents"), [["input", "target"], ["change", "target"]])

    def test_korean_contenteditable_fill_is_plain_text(self) -> None:
        self.fixture('<div id="target" contenteditable>before <b>rich</b></div>')
        self.assertTrue(self.call("NODE_FILL_FUNCTION", "#target", "한글 <입력>"))
        self.assertEqual(self.page.locator("#target").text_content(), "한글 <입력>")
        self.assertEqual(self.page.locator("#target").locator("*").count(), 0)
        self.assertEqual(self.page.evaluate("inputEvents"), [["input", "target"]])

    def test_check_respects_fieldset_disabled_and_emits_only_on_change(self) -> None:
        self.fixture(
            '<fieldset disabled><legend><input id="allowed" type="checkbox"></legend>'
            '<input id="target" type="checkbox"></fieldset>'
        )
        self.assertFalse(self.call("NODE_SET_CHECKED_FUNCTION", "#target", True))
        self.assertFalse(self.page.locator("#target").is_checked())
        self.assertEqual(self.page.evaluate("inputEvents"), [])
        self.assertTrue(self.call("NODE_SET_CHECKED_FUNCTION", "#allowed", True))
        self.assertTrue(self.call("NODE_SET_CHECKED_FUNCTION", "#allowed", True))
        self.assertEqual(self.page.evaluate("inputEvents"), [["input", "allowed"], ["change", "allowed"]])

    def test_native_checked_setter_reaches_controlled_checkbox_listener(self) -> None:
        self.fixture('<input id="target" type="checkbox">')
        self.page.evaluate(
            """() => {
                const native = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'checked');
                window.tracked = target.checked;
                window.observed = null;
                Object.defineProperty(target, 'checked', {
                    get() { return native.get.call(this); },
                    set(value) { tracked = value; native.set.call(this, value); }
                });
                target.addEventListener('input', () => {
                    if (target.checked !== tracked) observed = target.checked;
                });
            }"""
        )
        self.assertTrue(self.call("NODE_SET_CHECKED_FUNCTION", "#target", True))
        self.assertIs(self.page.evaluate("observed"), True)

    def test_select_respects_disabled_fieldset(self) -> None:
        self.fixture(
            '<fieldset disabled><select id="target">'
            '<option value="a">가</option><option value="b">나</option>'
            '</select></fieldset>'
        )
        self.assertFalse(self.call("NODE_SELECT_FUNCTION", "#target", ["b"]))
        self.assertEqual(self.page.locator("#target").input_value(), "a")
        self.assertEqual(self.page.evaluate("inputEvents"), [])

    def test_select_enabled_single_and_multiple_korean_values(self) -> None:
        for multiple in (False, True):
            with self.subTest(multiple=multiple):
                self.fixture(
                    f'<select id="target" {"multiple" if multiple else ""}>'
                    '<option value="가">가</option><option value="나">나</option>'
                    '<option value="다">다</option></select>'
                )
                values = ["나", "다"] if multiple else ["나"]
                self.assertTrue(self.call("NODE_SELECT_FUNCTION", "#target", values))
                self.assertEqual(
                    self.page.locator("#target").evaluate("el => Array.from(el.selectedOptions, option => option.value)"),
                    values,
                )
                self.assertEqual(self.page.evaluate("inputEvents"), [["input", "target"], ["change", "target"]])


if __name__ == "__main__":
    if not os.environ.get("BROWSERD_TEST_CHROMIUM"):
        print("BROWSERD_TEST_CHROMIUM is required for the live Chromium gate", file=sys.stderr)
        raise SystemExit(2)
    unittest.main(verbosity=2)
