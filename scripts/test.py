#!/usr/bin/env python3
"""Run repository tests from any current directory without installing the app.

Python tests use only the standard library. --browser additionally requires Node
and Playwright (with Chromium); PLAYWRIGHT_MODULE and CHROME_BIN may override
an existing module/browser installation. All browser targets are local fixtures.
"""
import argparse
import pathlib
import shutil
import subprocess
import sys
import unittest


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pattern',default='test_*.py',help='Python unittest filename pattern')
    parser.add_argument('-v','--verbose',action='store_true')
    parser.add_argument('--browser',action='store_true',help='Also run Node and Playwright fixture tests')
    args=parser.parse_args(argv)
    root=pathlib.Path(__file__).resolve().parents[1]
    sys.dont_write_bytecode=True
    for name in ('backend','installer','tests/python'):
        sys.path.insert(0,str(root/name))
    suite=unittest.defaultTestLoader.discover(str(root/'tests/python'),pattern=args.pattern)
    result=unittest.TextTestRunner(verbosity=2 if args.verbose else 1).run(suite)
    if not result.wasSuccessful():return 1
    if args.browser:
        node=shutil.which('node')
        if node is None:
            print('Browser tests require Node.js and Playwright with Chromium.',file=sys.stderr)
            return 2
        for path in sorted((root/'tests/browser').glob('test_*.cjs')):
            print('Browser fixture: '+path.name,flush=True)
            value=subprocess.run([node,str(path)],cwd=str(root))
            if value.returncode:return value.returncode
    return 0


if __name__=='__main__':raise SystemExit(main())
