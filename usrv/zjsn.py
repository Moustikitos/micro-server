# -*- coding: utf-8 -*-

# ~ https://medium.com/@busybus/zipjson-3ed15f8ea85d
# RA, 2019-01-22
# Compress and decompress a JSON object
# License: CC0 -- "No rights reserved"
# For zlib license, see https://docs.python.org/3/license.html

# changes :
#   - added bzip2 compression
#   - sort keys enabled
#   - remove white spaces

import zlib
import bz2
import json
import base64

ZIPJSON_KEY = 'base64(zip(o))'
BZ2JSON_KEY = 'base64(bz2(o))'


def _compress(j, method=lambda data: zlib.compress(data), key=ZIPJSON_KEY):

    return {
        key: base64.b64encode(
            method(
                json.dumps(j, separators=(',', ':')).encode('utf-8')
            )
        ).decode('ascii')
    }


def decompress(j, insist=False):
    try:
        assert len(j) == 1
        key, value = list(j.items())[0]
        assert key in [ZIPJSON_KEY, BZ2JSON_KEY]
    except Exception:
        if insist:
            raise RuntimeError("JSON not in the expected format")
        else:
            return j
    else:
        method = zlib.decompress if key == ZIPJSON_KEY else \
                 bz2.decompress if key == BZ2JSON_KEY else \
                 lambda *a, **k: b""

    try:
        j = method(base64.b64decode(value))
    except Exception:
        raise RuntimeError("can not decodeor decompress content")
    try:
        j = json.loads(j)
    except Exception:
        raise RuntimeError("can not interpret the decompressed content")

    return j


def bzip(j):
    return _compress(
        j, lambda data: bz2.compress(data, compresslevel=9), BZ2JSON_KEY
    )


def zip(j):
    return _compress(
        j, lambda data: zlib.compress(data), ZIPJSON_KEY
    )


if __name__ == '__main__':

    import unittest

    class TestJsonZipMethods(unittest.TestCase):
        # Unzipped
        unzipped = {'a': "A", 'b': "B"}

        # Zipped
        zipped = {ZIPJSON_KEY: "eJyrVkpUslJyVNJRSgLSTkq1ACPXA+8="}

        # List of items
        items = [123, "123", unzipped]

        def test_json_zip(self):
            self.assertEqual(self.zipped, _compress(self.unzipped))

        def test_json_unzip(self):
            self.assertEqual(self.unzipped, decompress(self.zipped))

        def test_json_zipunzip(self):
            for item in self.items:
                self.assertEqual(item, decompress(_compress(item)))

        def test_json_zipunzip_chinese(self):
            item = {'hello': u"你好"}
            self.assertEqual(item, decompress(_compress(item)))

        def test_json_unzip_insist_failure(self):
            for item in self.items:
                with self.assertRaises(RuntimeError):
                    decompress(item, insist=True)

        def test_json_unzip_noinsist_justified(self):
            for item in self.items:
                self.assertEqual(item, decompress(item, insist=False))

        def test_json_unzip_noinsist_unjustified(self):
            self.assertEqual(
                self.unzipped, decompress(self.zipped, insist=False)
            )

    unittest.main()
