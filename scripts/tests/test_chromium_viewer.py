"""Sandboxed Chromium viewer geometry and IME primitives; full owner gate is separate."""
import os
import sys
import unittest
import test_chromium_behavior as behavior


class ChromiumViewerBehavior(unittest.TestCase):
    setUpClass = classmethod(behavior.ChromiumHelperBehavior.setUpClass.__func__)
    setUp = behavior.ChromiumHelperBehavior.setUp

    def test_pinch_scale_input_uses_unscaled_css_coordinates(self):
        self.page.set_content('<button id="target" style="position:absolute;left:100px;top:100px;width:50px;height:50px">target</button>')
        self.page.evaluate('window.clicks=0; target.onclick=event=>{clicks++;window.lastX=event.clientX}; true')
        cdp = self.context.new_cdp_session(self.page)
        self.addCleanup(cdp.detach)
        cdp.send('Emulation.setPageScaleFactor', {'pageScaleFactor': 2})
        frames = []
        def frame(message):
            frames.append(message['metadata'])
            cdp.send('Page.screencastFrameAck', {'sessionId': message['sessionId']})
        cdp.on('Page.screencastFrame', frame)
        cdp.send('Page.startScreencast', {'format':'jpeg','quality':70,'maxWidth':1280,'maxHeight':720})
        self.addCleanup(lambda: cdp.send('Page.stopScreencast'))
        self.page.wait_for_timeout(150)
        self.assertTrue(frames)
        self.assertEqual(frames[-1]['deviceWidth'], 800)
        self.assertEqual(frames[-1]['pageScaleFactor'], 2)
        for kind in ['mousePressed', 'mouseReleased']:
            cdp.send('Input.dispatchMouseEvent', {'type':kind,'x':125,'y':125,'button':'left','clickCount':1})
        self.assertEqual(self.page.evaluate('clicks'), 1)
        self.assertEqual(self.page.evaluate('lastX'), 125)

    def test_enter_key_with_character_payload_creates_textarea_newline(self):
        self.page.set_content('<textarea id="target">a</textarea>')
        self.page.locator('#target').focus()
        self.page.evaluate('target.selectionStart=target.selectionEnd=1; true')
        cdp = self.context.new_cdp_session(self.page)
        self.addCleanup(cdp.detach)
        cdp.send('Input.dispatchKeyEvent', {'type':'keyDown','key':'Enter','code':'Enter','windowsVirtualKeyCode':13,'text':'\r'})
        cdp.send('Input.dispatchKeyEvent', {'type':'keyUp','key':'Enter','code':'Enter','windowsVirtualKeyCode':13})
        self.assertEqual(self.page.locator('#target').input_value(), 'a\n')

    def test_korean_composition_commits_once_and_empty_preedit_cancels(self):
        self.page.set_content('<input id="target">')
        self.page.locator('#target').focus()
        cdp = self.context.new_cdp_session(self.page)
        self.addCleanup(cdp.detach)
        cdp.send('Input.imeSetComposition', {'text':'한','selectionStart':1,'selectionEnd':1})
        cdp.send('Input.imeSetComposition', {'text':'한글','selectionStart':2,'selectionEnd':2})
        cdp.send('Input.insertText', {'text':'한글'})
        self.assertEqual(self.page.locator('#target').input_value(), '한글')
        cdp.send('Input.imeSetComposition', {'text':'취소','selectionStart':2,'selectionEnd':2})
        cdp.send('Input.imeSetComposition', {'text':'','selectionStart':0,'selectionEnd':0})
        self.assertEqual(self.page.locator('#target').input_value(), '한글')


if __name__ == '__main__':
    if not os.environ.get('BROWSERD_TEST_CHROMIUM'):
        print('BROWSERD_TEST_CHROMIUM is required for the live viewer gate', file=sys.stderr)
        raise SystemExit(2)
    unittest.main(verbosity=2)
