import unittest
from main import password_strength_checker

# IGNORE ALL OF THIS

class TestPasswordStrengthChecker(unittest.TestCase):
    def test_weak_password(self):
        self.assertEqual(password_strength_checker("123"), "Very Weak")

if __name__ == '__main__':
    unittest.main() 
