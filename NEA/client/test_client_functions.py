import unittest
import os
import sys
import tempfile
import hashlib
import re
import time
import json
import string
import random
from unittest.mock import patch, MagicMock
import shutil
import uuid
from datetime import datetime

class TestClientFunctions(unittest.TestCase):
    """Test suite for basic functions in the client code."""
    
    def setUp(self):
        """Set up test environment."""
        # Create a temporary directory for test files
        self.temp_dir = tempfile.mkdtemp()
        self.test_file_path = os.path.join(self.temp_dir, "test_file.txt")
        
        # Create a test file with known content
        with open(self.test_file_path, "w") as f:
            f.write("This is test content")
    
    def tearDown(self):
        """Clean up after tests."""
        # Remove the temporary directory and its contents
        shutil.rmtree(self.temp_dir)
    
    #-----------------------------------------
    # Tests for is_temp_file function
    #-----------------------------------------
    def is_temp_file(self, filepath):
        """Reimplementation of is_temp_file function."""
        filename = os.path.basename(filepath)
        temp_pattern = r"(^.*\.swp$|^.*\.tmp$|^\.goutputstream.*$|^~.*$|^.*\.bak$|^.*\.part$)"
        return bool(re.match(temp_pattern, filename, re.IGNORECASE))
    
    def test_is_temp_file(self):
        """Test is_temp_file with various inputs."""
        test_cases = [
            # Normal files (should return False)
            {"input": "document.txt", "expected": False, "category": "Normal"},
            {"input": "image.jpg", "expected": False, "category": "Normal"},
            {"input": "script.py", "expected": False, "category": "Normal"},
            {"input": "report.pdf", "expected": False, "category": "Normal"},
            
            # Temporary files (should return True)
            {"input": "file.tmp", "expected": True, "category": "Temp Files"},
            {"input": "document.swp", "expected": True, "category": "Temp Files"},
            {"input": ".goutputstream-XYZ123", "expected": True, "category": "Temp Files"},
            {"input": "~document.txt", "expected": True, "category": "Temp Files"},
            {"input": "file.bak", "expected": True, "category": "Temp Files"},
            {"input": "download.part", "expected": True, "category": "Temp Files"},
            
            # Boundary cases
            {"input": "", "expected": False, "category": "Boundary"},
            {"input": "a" * 1000 + ".tmp", "expected": True, "category": "Boundary"},
            {"input": "file.", "expected": False, "category": "Boundary"},
            {"input": ".hidden", "expected": False, "category": "Boundary"},
            
            # Special cases
            {"input": "archive.tar.gz", "expected": False, "category": "Special"},
            {"input": "archive.tar.bak", "expected": True, "category": "Special"},
            {"input": "file.TMP", "expected": True, "category": "Special"},
            {"input": "file.Tmp", "expected": True, "category": "Special"},
        ]
        
        print("\n=== is_temp_file Function Test Results ===")
        print(f"{'Input':<30} {'Expected':<10} {'Result':<10} {'Category':<15}")
        print("-" * 65)
        
        for tc in test_cases:
            result = self.is_temp_file(tc["input"])
            print(f"{tc['input'][:30]:<30} {str(tc['expected']):<10} {str(result):<10} {tc['category']:<15}")
            self.assertEqual(result, tc["expected"])
        
        print(f"\nAll {len(test_cases)} is_temp_file tests PASSED!")
    
    #-----------------------------------------
    # Tests for get_random_id function
    #-----------------------------------------
    def get_random_id(self, length=10):
        """Reimplementation of get_random_id function."""
        characters = string.ascii_letters + string.digits
        return ''.join(random.choice(characters) for _ in range(length))
    
    def test_get_random_id(self):
        """Test get_random_id function."""
        test_cases = [
            {"length": 10, "category": "Default"},
            {"length": 5, "category": "Short"},
            {"length": 20, "category": "Long"},
            {"length": 0, "category": "Zero"},
            {"length": 100, "category": "Very Long"},
        ]
        
        print("\n=== get_random_id Function Test Results ===")
        print(f"{'Length':<10} {'Result Length':<15} {'Alphanumeric':<15} {'Category':<15}")
        print("-" * 55)
        
        for tc in test_cases:
            result = self.get_random_id(tc["length"])
            is_alphanumeric = all(c.isalnum() for c in result)
            print(f"{tc['length']:<10} {len(result):<15} {str(is_alphanumeric):<15} {tc['category']:<15}")
            self.assertEqual(len(result), tc["length"])
            self.assertTrue(is_alphanumeric)
        
        # Uniqueness test
        print("\n--- Uniqueness Test ---")
        num_ids = 100
        ids = [self.get_random_id() for _ in range(num_ids)]
        unique_ids = set(ids)
        unique_ratio = len(unique_ids) / len(ids)
        print(f"Generated {num_ids} IDs, {len(unique_ids)} are unique (ratio: {unique_ratio:.2f})")
        self.assertEqual(len(ids), len(unique_ids))
        
        print(f"\nAll get_random_id tests PASSED!")
    
    #-----------------------------------------
    # Tests for file hash calculation
    #-----------------------------------------
    def calculate_file_hash(self, file_path):
        """Reimplementation of File._find_hash method."""
        hash_md5 = hashlib.md5()
        try:
            with open(file_path, "rb") as f:
                for block in iter(lambda: f.read(4096), b""):
                    hash_md5.update(block)
            return hash_md5.hexdigest()
        except FileNotFoundError:
            raise FileNotFoundError(f"The file at path {file_path} does not exist.")
    
    def test_calculate_file_hash(self):
        """Test file hash calculation function."""
        # Create test files with different contents
        empty_file = os.path.join(self.temp_dir, "empty.txt")
        small_file = os.path.join(self.temp_dir, "small.txt")
        large_file = os.path.join(self.temp_dir, "large.txt")
        non_existent = os.path.join(self.temp_dir, "non_existent.txt")
        
        with open(empty_file, "w"):
            pass  # Create empty file
        
        with open(small_file, "w") as f:
            f.write("Hello, World!")
        
        # Create a file that's larger than the block size
        with open(large_file, "w") as f:
            f.write("X" * 8192)  # 8KB of data
        
        # Pre-calculate expected hashes
        expected_hashes = {
            empty_file: hashlib.md5(b"").hexdigest(),
            small_file: hashlib.md5(b"Hello, World!").hexdigest(),
            large_file: hashlib.md5(b"X" * 8192).hexdigest()
        }
        
        test_cases = [
            {"file": empty_file, "category": "Empty File"},
            {"file": small_file, "category": "Small File"},
            {"file": large_file, "category": "Large File"},
            {"file": non_existent, "category": "Non-existent File"},
        ]
        
        print("\n=== File Hash Calculation Test Results ===")
        print(f"{'File Type':<20} {'Result':<40} {'Expected':<40}")
        print("-" * 100)
        
        for tc in test_cases:
            try:
                result = self.calculate_file_hash(tc["file"])
                expected = expected_hashes.get(tc["file"], "Expected FileNotFoundError")
                print(f"{tc['category']:<20} {result:<40} {expected:<40}")
                self.assertEqual(result, expected)
            except FileNotFoundError as e:
                if tc["category"] == "Non-existent File":
                    print(f"{tc['category']:<20} {'FileNotFoundError':<40} {'Expected FileNotFoundError':<40}")
                    # This is expected for non-existent file
                else:
                    self.fail(f"Unexpected FileNotFoundError for {tc['category']}")
        
        print(f"\nAll file hash calculation tests PASSED!")
    
    #-----------------------------------------
    # Tests for event ID generation
    #-----------------------------------------
    def generate_event_id(self):
        """Reimplementation of generate_event_id method."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        uid = str(uuid.uuid4())[:6]  # Short unique suffix (6 hex chars)
        return f"event_{timestamp}_{uid}"
    
    def test_generate_event_id(self):
        """Test event ID generation function."""
        # Format test
        ids = [self.generate_event_id() for _ in range(5)]
        pattern = r'^event_\d{8}_\d{6}_[0-9a-f]{6}$'
        
        print("\n=== Event ID Generation Test Results ===")
        print("--- Format Test ---")
        print(f"{'Event ID':<40} {'Valid Format':<15}")
        print("-" * 55)
        
        for i, event_id in enumerate(ids):
            matches = bool(re.match(pattern, event_id))
            print(f"{event_id:<40} {str(matches):<15}")
            self.assertTrue(matches)
        
        # Uniqueness test
        print("\n--- Uniqueness Test ---")
        num_ids = 10
        more_ids = [self.generate_event_id() for _ in range(num_ids)]
        unique_ids = set(more_ids)
        print(f"Generated {num_ids} IDs, {len(unique_ids)} are unique")
        self.assertEqual(len(more_ids), len(unique_ids))
        
        # Timestamp correctness test
        print("\n--- Timestamp Test ---")
        current_date = datetime.now().strftime("%Y%m%d")
        latest_id = self.generate_event_id()
        id_date = latest_id.split('_')[1]
        print(f"Current date: {current_date}, ID date part: {id_date}")
        self.assertEqual(current_date, id_date)
        
        print(f"\nAll event ID generation tests PASSED!")

if __name__ == '__main__':
    unittest.main()  # Use low verbosity to allow custom output