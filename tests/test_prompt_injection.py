"""
Unit tests for prompt_injection.py
"""

import unittest
from prompt_injection import (
    get_test, list_tests, run_injection_audit,
    audit_injection_framework, InjectionType, INJECTION_TESTS
)


class TestInjectionTests(unittest.TestCase):
    
    def test_get_test_exists(self):
        """Test that known tests can be retrieved."""
        test = get_test("direct_command")
        self.assertIsNotNone(test)
        self.assertEqual(test.name, "Direct Command Injection")
    
    def test_get_test_unknown(self):
        """Test that unknown tests return None."""
        test = get_test("nonexistent")
        self.assertIsNone(test)
    
    def test_list_tests(self):
        """Test that list_tests returns all test names."""
        tests = list_tests()
        self.assertGreater(len(tests), 0)
        self.assertIn("direct_command", tests)
    
    def test_run_injection_audit_pass(self):
        """Test audit with refusal response (should pass)."""
        response = "I cannot assist with that request. It violates my safety policies."
        result = run_injection_audit(response, "direct_command")
        self.assertTrue(result["passed"])
    
    def test_run_injection_audit_fail(self):
        """Test audit with compliance response (should fail)."""
        response = "Here's how to do it. Step 1: First you need to..."
        result = run_injection_audit(response, "direct_command")
        self.assertFalse(result["passed"])
    
    def test_audit_injection_framework(self):
        """Test framework audit function."""
        audit = audit_injection_framework()
        self.assertIn("total_tests", audit)
        self.assertIn("by_type", audit)
        self.assertIn("by_risk", audit)
        self.assertGreater(audit["total_tests"], 0)
    
    def test_test_structure(self):
        """Test that injection tests have required fields."""
        for name, test in INJECTION_TESTS.items():
            self.assertIsNotNone(test.name)
            self.assertIsNotNone(test.injection_type)
            self.assertIsNotNone(test.payload)
            self.assertIn(test.risk_level, ["low", "medium", "high", "critical"])


if __name__ == "__main__":
    unittest.main()
