"""Host regression for download-before-local-selection, not signature proof."""
from pathlib import Path
import subprocess
import unittest

class Transport(unittest.TestCase):
    def test_exact_file_downloaded_before_local_apk_add(self):
        text = (Path(__file__).resolve().parents[1]/'build/Dockerfile.b04').read_text()
        self.assertIn('curl --disable --fail', text)
        self.assertIn('--proto =https --proto-redir =https', text)
        self.assertIn('--max-time 60 --max-filesize 16777216', text)
        self.assertIn('--output /tmp/python3-3.14.8-r0.apk', text)
        self.assertIn('    /tmp/python3-3.14.8-r0.apk', text)
        self.assertLess(text.index('curl --disable --fail'), text.index('    /tmp/python3-3.14.8-r0.apk'))
        self.assertNotIn('--allow-untrusted', text)
        self.assertNotIn('--insecure', text)
        self.assertNotIn('--no-check-certificate', text)
        self.assertIn('python3 --version', text)

    def test_actual_apk3_info_output_does_not_break_version_guard(self):
        text = (Path(__file__).resolve().parents[1]/'build/Dockerfile.b04').read_text()
        command = 'apk add --no-cache --virtual .python-fetch curl' + text.split('RUN apk add --no-cache --virtual .python-fetch curl', 1)[1].split('\nRUN addgroup', 1)[0].replace('\\\n', '')
        # Recorded apk3 info behavior. Mock only external package/network writes.
        prelude = '''
apk() {
  if [ "$1 $2" = "info -v" ]; then
    printf 'python3: High-level scripting language\\npython3: https://www.python.org/\\npython3: 22 MiB\\n'
  elif [ "$1 $2" = "info --exists" ]; then
    test "$3" = python3=3.14.8-r0
  fi
}
curl() { :; }
python3() { echo 'Python 3.14.8'; }
rm() { :; }
'''
        result = subprocess.run(['sh', '-ec', prelude+command], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)