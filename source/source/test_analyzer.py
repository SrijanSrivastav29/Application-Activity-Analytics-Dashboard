import sys, tempfile, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # lets tests import from source\
import log_analyzer as la, audit

H = "timestamp,module,event_type,status,duration_ms\n"
OK = "2026-09-01T10:00:00,auth,LOGIN,SUCCESS,100\n"


class Tests(unittest.TestCase):
    # ---- Normal ----
    def test_normal_parse(self):
        df, rej = la.parse_log_text(H + OK)
        self.assertEqual((len(df), len(rej)), (1, 0))

    def test_metrics(self):
        t = H + "".join(f"2026-09-01T10:00:0{i},pay,API_CALL,{'ERROR' if i < 2 else 'SUCCESS'},{10*(i+1)}\n" for i in range(4))
        s = la.summarize(la.parse_log_text(t)[0]).iloc[0]
        self.assertEqual((s.events, s.errors, s.error_rate, s.median_ms), (4, 2, 0.5, 25.0))

    # ---- Empty ----
    def test_empty_file(self):
        df, rej = la.parse_log_text("")
        self.assertTrue(df.empty)
        self.assertTrue(la.summarize(df).empty)

    def test_header_only(self):
        df, rej = la.parse_log_text(H)
        self.assertTrue(df.empty)

    # ---- Invalid input ----
    def test_missing_header_column(self):
        with self.assertRaises(ValueError):
            la.parse_log_text("timestamp,module\n1,2\n")

    def test_invalid_timestamp(self):
        _, rej = la.parse_log_text(H + "bad,auth,LOGIN,SUCCESS,1\n")
        self.assertEqual(rej[0]["reason"], "invalid timestamp")

    def test_missing_field(self):
        _, rej = la.parse_log_text(H + "2026-09-01T10:00:00,auth,LOGIN,,1\n")
        self.assertIn("missing", rej[0]["reason"])

    def test_malicious_looking_module_rejected(self):
        _, rej = la.parse_log_text(H + "2026-09-01T10:00:00,'; DROP TABLE x;--,LOGIN,SUCCESS,1\n")
        self.assertEqual(len(rej), 1)

    # ---- Boundary / extreme ----
    def test_extreme_and_negative_duration(self):
        _, rej = la.parse_log_text(H + "2026-09-01T10:00:00,auth,LOGIN,SUCCESS,99999999\n"
                                       "2026-09-01T10:00:00,auth,LOGIN,SUCCESS,-1\n")
        self.assertEqual(len(rej), 2)

    def test_duration_boundary_accepted(self):
        df, _ = la.parse_log_text(H + f"2026-09-01T10:00:00,auth,LOGIN,SUCCESS,{la.MAX_DURATION_MS}\n")
        self.assertEqual(len(df), 1)

    def test_threshold_boundary(self):
        t = H + "2026-09-01T10:00:00,a,X,ERROR,1\n2026-09-01T10:00:01,a,X,SUCCESS,1\n"  # exactly 50%
        s = la.summarize(la.parse_log_text(t)[0])
        self.assertFalse(la.flag_modules(s, 0.5)["flagged"].iloc[0])   # equal -> NOT flagged
        self.assertTrue(la.flag_modules(s, 0.49)["flagged"].iloc[0])   # above -> flagged

    def test_invalid_threshold(self):
        with self.assertRaises(ValueError):
            la.flag_modules(la.summarize(la.parse_log_text(H + OK)[0]), 1.5)

    # ---- Security controls ----
    def test_oversize_file(self):
        with self.assertRaises(ValueError):
            la.parse_log_bytes(b"x" * (la.MAX_FILE_BYTES + 1))

    def test_csv_injection_sanitized(self):
        self.assertEqual(la.sanitize_cell("=1+1"), "'=1+1")
        self.assertEqual(la.sanitize_cell("auth"), "auth")

    def test_audit_parameterized(self):
        db = Path(tempfile.mkdtemp()) / "a.db"
        audit.record_filter(db, ["auth'; DROP TABLE filter_audit;--"], "ALL", "2026-09-01", "2026-09-02", 0.15, 5)
        self.assertEqual(len(audit.recent(db)), 1)   # table survived the injection attempt


if __name__ == "__main__":
    unittest.main(verbosity=2)