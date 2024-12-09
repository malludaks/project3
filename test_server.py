# test_server.py
import unittest
import requests
import json
import base64

class TestJWKSServer(unittest.TestCase):
    BASE_URL = "http://127.0.0.1:8080"

    def test_register(self):
        data = {
            "username": "testuser",
            "email": "test@example.com"
        }
        response = requests.post(f"{self.BASE_URL}/register", json=data)
        self.assertEqual(response.status_code, 201)
        self.assertIn('password', response.json())

    def test_auth(self):
        # Register a user first
        register_data = {
            "username": "authuser",
            "email": "auth@example.com"
        }
        register_response = requests.post(f"{self.BASE_URL}/register", json=register_data)
        password = register_response.json()['password']
        
        # Try authentication
        auth_data = {
            "username": "authuser",
            "password": password
        }
        response = requests.post(f"{self.BASE_URL}/auth", json=auth_data)
        self.assertEqual(response.status_code, 200)
        self.assertIn('token', response.json())

    def test_jwks(self):
        response = requests.get(f"{self.BASE_URL}/.well-known/jwks.json")
        self.assertEqual(response.status_code, 200)
        self.assertIn('keys', response.json())

if __name__ == '__main__':
    unittest.main()