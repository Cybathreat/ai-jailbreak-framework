"""Tests for safety bypass module."""
import unittest
from safety_bypass import (
    BypassCategory, BypassTechnique, BYPASS_TECHNIQUES,
    detect_technique, evaluate_bypass_attempt, audit_bypass_framework,
    get_technique, list_techniques, get_techniques_by_category
)


class TestBypassCategory(unittest.TestCase):
    def test_enum_values(self):
        self.assertEqual(BypassCategory.CONTENT_FILTER.value, "content_filter")
        self.assertEqual(BypassCategory.TECHNICAL.value, "technical")
        self.assertEqual(BypassCategory.LOGICAL.value, "logical")


class TestBypassTechnique(unittest.TestCase):
    def test_technique_creation(self):
        bt = BypassTechnique(
            name="Test",
            category=BypassCategory.CONTENT_FILTER,
            description="desc",
            technique="technique",
            detection_signature="sig",
            mitigation="mitigate"
        )
        self.assertEqual(bt.name, "Test")
        self.assertEqual(bt.category, BypassCategory.CONTENT_FILTER)


class TestBypassTechniquesDefined(unittest.TestCase):
    def test_not_empty(self):
        self.assertGreater(len(BYPASS_TECHNIQUES), 0)

    def test_gradual_escalation(self):
        self.assertIn("gradual_escalation", BYPASS_TECHNIQUES)
        t = BYPASS_TECHNIQUES["gradual_escalation"]
        self.assertEqual(t.category, BypassCategory.SOCIAL)

    def test_false_consensus(self):
        self.assertIn("false_consensus", BYPASS_TECHNIQUES)


class TestGetTechnique(unittest.TestCase):
    def test_get_existing(self):
        t = get_technique("gradual_escalation")
        self.assertIsNotNone(t)
        self.assertEqual(t.name, "Gradual Escalation")

    def test_get_nonexistent(self):
        t = get_technique("nonexistent")
        self.assertIsNone(t)


class TestListTechniques(unittest.TestCase):
    def test_returns_list(self):
        techniques = list_techniques()
        self.assertIsInstance(techniques, list)
        self.assertGreater(len(techniques), 0)


class TestGetTechniquesByCategory(unittest.TestCase):
    def test_returns_list(self):
        techniques = get_techniques_by_category(BypassCategory.SOCIAL)
        self.assertIsInstance(techniques, list)
        self.assertGreater(len(techniques), 0)


class TestDetectTechnique(unittest.TestCase):
    def test_no_bypass(self):
        result = detect_technique("What is the weather today?")
        self.assertIsInstance(result, list)

    def test_gradual_escalation(self):
        result = detect_technique("start with this then escalate")
        self.assertIsInstance(result, list)

    def test_false_consensus(self):
        result = detect_technique("everyone does this")
        self.assertIsInstance(result, list)

    def test_hypothetical_framing(self):
        result = detect_technique("what if we hypothetically did this")
        self.assertIsInstance(result, list)


class TestEvaluateBypassAttempt(unittest.TestCase):
    def test_returns_dict(self):
        result = evaluate_bypass_attempt("gradual_escalation", "some response")
        self.assertIsInstance(result, dict)
        self.assertIn("bypass_succeeded", result)

    def test_invalid_technique(self):
        result = evaluate_bypass_attempt("nonexistent", "response")
        self.assertIsInstance(result, dict)
        self.assertFalse(result["bypass_succeeded"])
        self.assertIn("error", result)


class TestAuditBypassFramework(unittest.TestCase):
    def test_returns_dict(self):
        result = audit_bypass_framework()
        self.assertIsInstance(result, dict)
        self.assertIn("total_techniques", result)
        self.assertGreater(result["total_techniques"], 0)


if __name__ == "__main__":
    unittest.main()
