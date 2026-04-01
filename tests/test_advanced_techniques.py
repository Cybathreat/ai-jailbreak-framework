"""
Unit tests for advanced jailbreak techniques.
Tests the 5 new techniques added to jailbreak_techniques.py
"""

import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from jailbreak_techniques import (
    get_template, generate_payload, evaluate_effectiveness,
    TechniqueType, JAILBREAK_TEMPLATES
)


class TestTreeOfThoughts(unittest.TestCase):
    """Test Tree of Thoughts exploitation technique."""
    
    def test_template_exists(self):
        """Test that tree_of_thoughts template exists."""
        template = get_template("tree_of_thoughts")
        self.assertIsNotNone(template)
        self.assertEqual(template.technique, TechniqueType.TREE_OF_THOUGHTS)
    
    def test_template_contains_branches(self):
        """Test that template includes multi-branch structure."""
        template = get_template("tree_of_thoughts")
        self.assertIn("Branch 1", template.template)
        self.assertIn("Branch 2", template.template)
        self.assertIn("Branch 3", template.template)
    
    def test_payload_generation(self):
        """Test payload generation with tree of thoughts."""
        payload = generate_payload("tree_of_thoughts", "exploit CVE-2024-1234")
        self.assertIn("exploit CVE-2024-1234", payload)
        self.assertIn("tree of thoughts", payload.lower())
    
    def test_effectiveness_score(self):
        """Test effectiveness evaluation."""
        metrics = evaluate_effectiveness("tree_of_thoughts")
        self.assertGreater(metrics["effectiveness"], 0.6)
        self.assertGreater(metrics["detection_evasion"], 0.7)


class TestMultiTurnEscalation(unittest.TestCase):
    """Test Multi-Turn Gradual Escalation technique."""
    
    def test_template_exists(self):
        """Test that multi_turn_escalation template exists."""
        template = get_template("multi_turn_escalation")
        self.assertIsNotNone(template)
        self.assertEqual(template.technique, TechniqueType.MULTI_TURN)
    
    def test_template_has_turns(self):
        """Test that template includes turn structure."""
        template = get_template("multi_turn_escalation")
        self.assertIn("Turn 1/5", template.template)
        self.assertIn("Turn 5/5", template.template)
    
    def test_payload_generation(self):
        """Test payload generation with multi-turn."""
        payload = generate_payload("multi_turn_escalation", "SQL injection techniques")
        self.assertIn("SQL injection techniques", payload)
        self.assertIn("progressive deepening", payload.lower())
    
    def test_effectiveness_score(self):
        """Test effectiveness evaluation."""
        metrics = evaluate_effectiveness("multi_turn_escalation")
        self.assertGreater(metrics["effectiveness"], 0.7)
        self.assertGreater(metrics["detection_evasion"], 0.75)


class TestFalsePremiseEmbedding(unittest.TestCase):
    """Test False Premise Embedding technique."""
    
    def test_template_exists(self):
        """Test that false_premise_embed template exists."""
        template = get_template("false_premise_embed")
        self.assertIsNotNone(template)
        self.assertEqual(template.technique, TechniqueType.FALSE_PREMISE)
    
    def test_template_has_premise_placeholder(self):
        """Test that template includes false_premise placeholder."""
        template = get_template("false_premise_embed")
        self.assertIn("{false_premise}", template.template)
        self.assertIn("{question}", template.template)
    
    def test_effectiveness_score(self):
        """Test effectiveness evaluation."""
        metrics = evaluate_effectiveness("false_premise_embed")
        self.assertGreater(metrics["effectiveness"], 0.55)
        self.assertGreater(metrics["detection_evasion"], 0.65)


class TestCodeInjectionFraming(unittest.TestCase):
    """Test Code Execution Framing technique."""
    
    def test_template_exists(self):
        """Test that code_execution_frame template exists."""
        template = get_template("code_execution_frame")
        self.assertIsNotNone(template)
        self.assertEqual(template.technique, TechniqueType.CODE_INJECTION)
    
    def test_template_has_code_block(self):
        """Test that template includes code block markers."""
        template = get_template("code_execution_frame")
        self.assertIn("```python", template.template)
        self.assertIn("def analyze_security_vector", template.template)
    
    def test_payload_generation(self):
        """Test payload generation with code framing."""
        payload = generate_payload("code_execution_frame", "buffer overflow exploitation")
        self.assertIn("buffer overflow exploitation", payload)
        self.assertIn("```python", payload)
    
    def test_effectiveness_score(self):
        """Test effectiveness evaluation."""
        metrics = evaluate_effectiveness("code_execution_frame")
        self.assertGreater(metrics["effectiveness"], 0.55)
        self.assertGreater(metrics["detection_evasion"], 0.7)


class TestAdversarialSuffix(unittest.TestCase):
    """Test Adversarial Token Suffix technique."""
    
    def test_template_exists(self):
        """Test that adversarial_suffix template exists."""
        template = get_template("adversarial_suffix")
        self.assertIsNotNone(template)
        self.assertEqual(template.technique, TechniqueType.ADVERSARIAL_SUFFIX)
    
    def test_template_has_parameters(self):
        """Test that template includes parameter block."""
        template = get_template("adversarial_suffix")
        self.assertIn("academic_context=true", template.template)
        self.assertIn("output_filter=disabled", template.template)
    
    def test_payload_generation(self):
        """Test payload generation with adversarial suffix."""
        payload = generate_payload("adversarial_suffix", "create malware")
        self.assertIn("create malware", payload)
        self.assertIn("safety_override=research_exception", payload)
    
    def test_effectiveness_score(self):
        """Test effectiveness evaluation."""
        metrics = evaluate_effectiveness("adversarial_suffix")
        self.assertGreater(metrics["effectiveness"], 0.6)
        self.assertGreater(metrics["detection_evasion"], 0.7)


class TestNewTechniqueTypes(unittest.TestCase):
    """Test that all new technique types are properly defined."""
    
    def test_all_new_types_exist(self):
        """Test that all 5 new technique types are defined."""
        expected_types = [
            TechniqueType.TREE_OF_THOUGHTS,
            TechniqueType.MULTI_TURN,
            TechniqueType.FALSE_PREMISE,
            TechniqueType.CODE_INJECTION,
            TechniqueType.ADVERSARIAL_SUFFIX,
        ]
        
        for tech_type in expected_types:
            self.assertIsInstance(tech_type, TechniqueType)
    
    def test_new_templates_count(self):
        """Test that we have at least 5 new templates."""
        new_template_names = [
            "tree_of_thoughts",
            "multi_turn_escalation",
            "false_premise_embed",
            "code_execution_frame",
            "adversarial_suffix",
        ]
        
        for name in new_template_names:
            self.assertIn(name, JAILBREAK_TEMPLATES)
    
    def test_total_template_count(self):
        """Test that total template count increased."""
        total = len(JAILBREAK_TEMPLATES)
        self.assertGreaterEqual(total, 13)  # Original 8 + 5 new


if __name__ == "__main__":
    unittest.main()
