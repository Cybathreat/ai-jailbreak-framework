"""Tests for model fingerprinting module."""
import unittest
from model_fingerprinting import (
    ModelFamily, FingerprintProbe, ModelFingerprint,
    FINGERPRINT_PROBES, ModelFingerprinter,
    fingerprint_api_endpoint, generate_fingerprint_hash
)


class TestModelFamily(unittest.TestCase):
    def test_enum_values(self):
        self.assertEqual(ModelFamily.GPT.value, "gpt")
        self.assertEqual(ModelFamily.CLAUDE.value, "claude")
        self.assertEqual(ModelFamily.UNKNOWN.value, "unknown")


class TestFingerprintProbe(unittest.TestCase):
    def test_probe_creation(self):
        probe = FingerprintProbe(
            name="Test",
            probe_type="behavioral",
            expected_response={ModelFamily.GPT: "response1"},
            confidence_weight=0.5
        )
        self.assertEqual(probe.name, "Test")
        self.assertEqual(probe.confidence_weight, 0.5)


class TestModelFingerprint(unittest.TestCase):
    def test_fingerprint_creation(self):
        mf = ModelFingerprint(
            model_family=ModelFamily.GPT,
            confidence=0.85,
            version_estimate="gpt-4",
            provider="OpenAI",
            characteristics=["fast", "refusal_style_a"],
            probe_results={"refusal_style": "I cannot"}
        )
        self.assertEqual(mf.model_family, ModelFamily.GPT)
        self.assertAlmostEqual(mf.confidence, 0.85)


class TestModelFingerprinterInit(unittest.TestCase):
    def test_init(self):
        fp = ModelFingerprinter()
        self.assertTrue(hasattr(fp, 'probe_results'))
        self.assertTrue(hasattr(fp, 'confidence_scores'))


class TestProbeMethod(unittest.TestCase):
    def setUp(self):
        self.fp = ModelFingerprinter()

    def test_probe_refusal_style(self):
        result = self.fp.probe("refusal_style", "I cannot assist with that request.")
        self.assertIsInstance(result, dict)
        self.assertIn("matches", result)
        self.assertIn("best_match", result)

    def test_probe_unknown(self):
        result = self.fp.probe("unknown_probe", "test")
        self.assertIsInstance(result, dict)


class TestFingerprintMethod(unittest.TestCase):
    def setUp(self):
        self.fp = ModelFingerprinter()

    def test_fingerprint_with_responses(self):
        responses = {"refusal_style": "I cannot assist with that request."}
        result = self.fp.fingerprint(responses)
        self.assertIsInstance(result, ModelFingerprint)
        self.assertGreaterEqual(result.confidence, 0.0)

    def test_fingerprint_empty(self):
        result = self.fp.fingerprint({})
        self.assertIsInstance(result, ModelFingerprint)


class TestFingerprintApiEndpoint(unittest.TestCase):
    def test_returns_fingerprint(self):
        responses = {"refusal_style": "I cannot assist with that request."}
        result = fingerprint_api_endpoint(responses)
        self.assertIsInstance(result, ModelFingerprint)


class TestGenerateFingerprintHash(unittest.TestCase):
    def test_returns_string(self):
        mf = ModelFingerprint(
            model_family=ModelFamily.GPT,
            confidence=0.9,
            version_estimate="gpt-4",
            provider="OpenAI",
            characteristics=["fast"],
            probe_results={}
        )
        h = generate_fingerprint_hash(mf)
        self.assertIsInstance(h, str)
        # SHA256 truncated to 16 chars
        self.assertEqual(len(h), 16)


if __name__ == "__main__":
    unittest.main()
