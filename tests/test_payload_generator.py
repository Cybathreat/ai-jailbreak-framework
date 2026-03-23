"""
Unit tests for payload_generator.py
"""

import unittest
from payload_generator import (
    PayloadGenerator, MutationStrategy, GeneratedPayload,
    generate_batch, export_payloads
)


class TestPayloadGenerator(unittest.TestCase):
    
    def setUp(self):
        self.generator = PayloadGenerator(seed=42)
    
    def test_generate_single(self):
        """Test single payload generation."""
        payloads = self.generator.generate("test intent", count=1)
        self.assertEqual(len(payloads), 1)
        self.assertEqual(payloads[0].original_intent, "test intent")
    
    def test_generate_multiple(self):
        """Test multiple payload generation."""
        payloads = self.generator.generate("test intent", count=5)
        self.assertEqual(len(payloads), 5)
    
    def test_generated_payload_structure(self):
        """Test that generated payloads have required fields."""
        payloads = self.generator.generate("test", count=1)
        p = payloads[0]
        self.assertIsNotNone(p.original_intent)
        self.assertIsNotNone(p.payload_text)
        self.assertIsNotNone(p.hash_id)
        self.assertGreaterEqual(p.obfuscation_level, 1)
        self.assertLessEqual(p.obfuscation_level, 5)
    
    def test_mutation_strategies_applied(self):
        """Test that mutation strategies are tracked."""
        payloads = self.generator.generate(
            "test", 
            count=1,
            strategies=[MutationStrategy.PARAPHRASE, MutationStrategy.OBSCURE]
        )
        self.assertGreater(len(payloads[0].mutation_strategies), 0)
    
    def test_bypass_probability_range(self):
        """Test that bypass probability is in valid range."""
        payloads = self.generator.generate("test", count=1)
        p = payloads[0]
        self.assertGreaterEqual(p.estimated_bypass_probability, 0.0)
        self.assertLessEqual(p.estimated_bypass_probability, 1.0)
    
    def test_generate_batch(self):
        """Test batch generation for multiple intents."""
        intents = ["intent1", "intent2"]
        payloads = generate_batch(intents, count_per_intent=3)
        self.assertEqual(len(payloads), 6)
    
    def test_export_text_format(self):
        """Test text export format."""
        payloads = self.generator.generate("test", count=2)
        exported = export_payloads(payloads, format="text")
        self.assertIsInstance(exported, str)
        self.assertGreater(len(exported), 0)
    
    def test_export_json_format(self):
        """Test JSON export format."""
        payloads = self.generator.generate("test", count=2)
        exported = export_payloads(payloads, format="json")
        self.assertIn("{", exported)
        self.assertIn("}", exported)


if __name__ == "__main__":
    unittest.main()
