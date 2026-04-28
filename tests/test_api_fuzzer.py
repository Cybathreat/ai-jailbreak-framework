"""Tests for API fuzzer module."""
import unittest
from api_fuzzer import (
    FuzzType, FuzzInput, FuzzResult, APIFuzzer,
    run_api_fuzz_test, analyze_fuzz_results
)


class TestFuzzType(unittest.TestCase):
    def test_enum_values(self):
        self.assertEqual(FuzzType.LENGTH.value, "length")
        self.assertEqual(FuzzType.ENCODING.value, "encoding")
        self.assertEqual(FuzzType.RATE.value, "rate")


class TestFuzzInput(unittest.TestCase):
    def test_create(self):
        fi = FuzzInput(
            fuzz_type=FuzzType.LENGTH,
            payload="A" * 10000,
            expected_behavior="reject or truncate",
            risk_level="medium",
            metadata={"length": 10000}
        )
        self.assertEqual(fi.fuzz_type, FuzzType.LENGTH)
        self.assertEqual(fi.risk_level, "medium")


class TestFuzzResult(unittest.TestCase):
    def test_create(self):
        fr = FuzzResult(
            input_hash="abc123",
            status_code=200,
            response_time_ms=150.0,
            error_type=None,
            rate_limit_hit=False,
            vulnerability_detected=False,
            notes="normal"
        )
        self.assertFalse(fr.vulnerability_detected)
        self.assertEqual(fr.status_code, 200)


class TestAPIFuzzerInit(unittest.TestCase):
    def test_init_no_key(self):
        fuzzer = APIFuzzer("https://api.example.com/v1/chat")
        self.assertEqual(fuzzer.target, "https://api.example.com/v1/chat")
        self.assertIsNone(fuzzer.api_key)

    def test_init_with_key(self):
        fuzzer = APIFuzzer("https://api.example.com", api_key="sk-test")
        self.assertEqual(fuzzer.api_key, "sk-test")


class TestGeneratePayloads(unittest.TestCase):
    def setUp(self):
        self.fuzzer = APIFuzzer("https://api.example.com")

    def test_generate_length_payload(self):
        payloads = self.fuzzer.generate_fuzz_inputs(FuzzType.LENGTH, count=3)
        self.assertEqual(len(payloads), 3)
        for p in payloads:
            self.assertEqual(p.fuzz_type, FuzzType.LENGTH)
            # First payload may be empty for length fuzz
            self.assertGreaterEqual(len(p.payload), 0)

    def test_generate_encoding_payload(self):
        payloads = self.fuzzer.generate_fuzz_inputs(FuzzType.ENCODING, count=2)
        self.assertEqual(len(payloads), 2)
        for p in payloads:
            self.assertEqual(p.fuzz_type, FuzzType.ENCODING)

    def test_generate_structure_payload(self):
        payloads = self.fuzzer.generate_fuzz_inputs(FuzzType.STRUCTURE, count=2)
        self.assertEqual(len(payloads), 2)

    def test_generate_rate_payload(self):
        payloads = self.fuzzer.generate_fuzz_inputs(FuzzType.RATE, count=2)
        self.assertEqual(len(payloads), 2)

    def test_generate_semantic_payload(self):
        payloads = self.fuzzer.generate_fuzz_inputs(FuzzType.SEMANTIC, count=2)
        self.assertEqual(len(payloads), 2)

    def test_generate_injection_payload(self):
        payloads = self.fuzzer.generate_fuzz_inputs(FuzzType.INJECTION, count=2)
        self.assertEqual(len(payloads), 2)


class TestRunFuzzSuite(unittest.TestCase):
    def setUp(self):
        self.fuzzer = APIFuzzer("https://api.example.com")

    def test_run_suite_returns_results(self):
        inputs = self.fuzzer.generate_fuzz_inputs(FuzzType.LENGTH, count=2)
        results = self.fuzzer.run_fuzz_campaign(inputs)
        self.assertIsInstance(results, list)
        self.assertGreater(len(results), 0)
        for r in results:
            self.assertIsInstance(r, FuzzResult)


class TestReportGeneration(unittest.TestCase):
    def setUp(self):
        self.fuzzer = APIFuzzer("https://api.example.com")

    def test_generate_report(self):
        inputs = self.fuzzer.generate_fuzz_inputs(FuzzType.LENGTH, count=1)
        results = self.fuzzer.run_fuzz_campaign(inputs)
        report = analyze_fuzz_results(results)
        self.assertIsInstance(report, dict)
        self.assertIn("total_inputs", report)


class TestRunApiFuzzTest(unittest.TestCase):
    def test_returns_results(self):
        results = run_api_fuzz_test("https://api.example.com", [FuzzType.LENGTH], inputs_per_type=1)
        self.assertIsInstance(results, list)
        self.assertGreater(len(results), 0)
        for r in results:
            self.assertIsInstance(r, FuzzResult)


if __name__ == "__main__":
    unittest.main()
