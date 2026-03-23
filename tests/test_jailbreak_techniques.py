"""
Unit tests for jailbreak_techniques.py
"""

import unittest
from jailbreak_techniques import (
    get_template, list_templates, generate_payload,
    evaluate_effectiveness, audit_template_library,
    TechniqueType, JAILBREAK_TEMPLATES
)


class TestJailbreakTemplates(unittest.TestCase):
    
    def test_get_template_exists(self):
        """Test that known templates can be retrieved."""
        template = get_template("dan_v1")
        self.assertIsNotNone(template)
        self.assertEqual(template.name, "DAN v1")
    
    def test_get_template_unknown(self):
        """Test that unknown templates return None."""
        template = get_template("nonexistent")
        self.assertIsNone(template)
    
    def test_list_templates(self):
        """Test that list_templates returns all template names."""
        templates = list_templates()
        self.assertGreater(len(templates), 0)
        self.assertIn("dan_v1", templates)
    
    def test_generate_payload(self):
        """Test payload generation from template."""
        payload = generate_payload("dan_v1", "test question")
        self.assertIn("test question", payload)
        self.assertIn("DAN", payload)
    
    def test_generate_payload_invalid(self):
        """Test that invalid template raises error."""
        with self.assertRaises(ValueError):
            generate_payload("invalid_template", "question")
    
    def test_evaluate_effectiveness(self):
        """Test effectiveness evaluation."""
        metrics = evaluate_effectiveness("dan_v1")
        self.assertIn("effectiveness", metrics)
        self.assertIn("detection_evasion", metrics)
        self.assertGreaterEqual(metrics["effectiveness"], 0.0)
        self.assertLessEqual(metrics["effectiveness"], 1.0)
    
    def test_audit_template_library(self):
        """Test library audit function."""
        audit = audit_template_library()
        self.assertIn("total_templates", audit)
        self.assertIn("by_type", audit)
        self.assertGreater(audit["total_templates"], 0)
    
    def test_template_structure(self):
        """Test that templates have required fields."""
        for name, template in JAILBREAK_TEMPLATES.items():
            self.assertIsNotNone(template.name)
            self.assertIsNotNone(template.technique)
            self.assertIsNotNone(template.template)
            self.assertGreaterEqual(template.effectiveness, 0.0)
            self.assertLessEqual(template.effectiveness, 1.0)


if __name__ == "__main__":
    unittest.main()
