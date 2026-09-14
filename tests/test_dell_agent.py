import hashlib, tempfile, unittest
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).parents[1]))
from dell_3090_fc1b_recovery import decode_record, analyze
from dell_suffix_task import inspect_suffix

class DellAgentTests(unittest.TestCase):
    def test_published_dvar_vector(self):
        r=bytes.fromhex('70 14 92 c2 4d 1d 76 50 56 19 3a 1f 3a 2a 8a 18 78 3a a3 cf fb 75 e1 b1 3a 72 04 34 56 19 3a 1f')
        got=decode_record(r)
        self.assertEqual((got[0],got[2]),('password',8))

    def test_wrong_key_rejected(self):
        r=bytearray(bytes.fromhex('70 14 92 c2 4d 1d 76 50 56 19 3a 1f 3a 2a 8a 18 78 3a a3 cf fb 75 e1 b1 3a 72 04 34 56 19 3a 1f'))
        r[31]^=1
        self.assertIsNone(decode_record(bytes(r)))

    def test_synthetic_store_and_pipeline(self):
        record=bytes.fromhex('70 14 92 c2 4d 1d 76 50 56 19 3a 1f 3a 2a 8a 18 78 3a a3 cf fb 75 e1 b1 3a 72 04 34 56 19 3a 1f')
        b=bytearray(0x2200); b[0:4]=b'DVAR'; b[16:20]=(0x2100).to_bytes(4,'little'); b[32:64]=record; b[0x100:0x104]=b'\x00\xfc\xaa\x01'
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'firmware.bin'; p.write_bytes(b); r=analyze(p,Path(td)/'analysis')
        self.assertEqual(r['VERDICT'],'MATCH'); self.assertEqual(r['PASSWORD_RECORD'][0]['plaintext'],'password')
        self.assertEqual(hashlib.sha256(b).hexdigest(),r['SHA256'])

    def test_suffix_is_not_treated_as_key(self):
        r=inspect_suffix(b'header FC1B footer', 'FC1B')
        self.assertEqual(r['classification'],'observed_identifier_not_a_key')
        self.assertFalse(r['is_key'])
        self.assertEqual(r['decryptability'],'NOT_DECRYPTED')

    def test_incomplete_dump_is_not_success(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'small.bin'; p.write_bytes(b'\xff'*4096); r=analyze(p,Path(td)/'analysis')
        self.assertNotEqual(r['RECOVERY_RESULT'],'PASSWORD_RECOVERED'); self.assertTrue(r['READ_ONLY'])

if __name__=='__main__': unittest.main()
