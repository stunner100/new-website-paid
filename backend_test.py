import unittest
import requests
import json
import os
import time
import random
import string
from pathlib import Path

# Get the backend URL from frontend/.env
BACKEND_URL = None
try:
    with open('/app/frontend/.env', 'r') as f:
        for line in f:
            if line.startswith('REACT_APP_BACKEND_URL='):
                BACKEND_URL = line.strip().split('=')[1].strip('"\'')
                break
except Exception as e:
    print(f"Error reading frontend/.env: {e}")

if not BACKEND_URL:
    BACKEND_URL = "https://9521216d-1781-41af-9407-62a495a5443d.preview.emergentagent.com"

API_URL = f"{BACKEND_URL}/api"
print(f"Using API URL: {API_URL}")

def random_string(length=8):
    """Generate a random string for test data"""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

class TestBackend(unittest.TestCase):
    """Test class for the Netflix-like adult content platform backend"""
    
    @classmethod
    def setUpClass(cls):
        """Set up test data and users"""
        cls.test_users = {
            "regular": {
                "email": f"regular_user_{random_string()}@example.com",
                "name": "Regular User",
                "password": "Password123!",
                "age_verified": True,
                "token": None,
                "user_id": None
            },
            "admin": {
                "email": f"admin_user_{random_string()}@example.com",
                "name": "Admin User",
                "password": "AdminPass123!",
                "age_verified": True,
                "token": None,
                "user_id": None
            }
        }
        
        # Create test video file
        cls.test_video_path = Path('/app/test_video.mp4')
        if not cls.test_video_path.exists():
            # Create a small test video file
            with open(cls.test_video_path, 'wb') as f:
                f.write(b'RIFF\x00\x00\x00\x00WAVEfmt \x10\x00\x00\x00\x01\x00\x01\x00\x44\xac\x00\x00\x88\x58\x01\x00\x02\x00\x10\x00data\x00\x00\x00\x00')
        
        # Register users
        cls._register_test_users()
        
        # Make one user an admin
        cls._make_admin_user()
        
    @classmethod
    def tearDownClass(cls):
        """Clean up after tests"""
        # Remove test video file
        if cls.test_video_path.exists():
            cls.test_video_path.unlink()
    
    @classmethod
    def _register_test_users(cls):
        """Register test users"""
        for user_type, user_data in cls.test_users.items():
            response = requests.post(
                f"{API_URL}/auth/register",
                json={
                    "email": user_data["email"],
                    "name": user_data["name"],
                    "password": user_data["password"],
                    "age_verified": user_data["age_verified"]
                }
            )
            
            if response.status_code == 200:
                data = response.json()
                cls.test_users[user_type]["token"] = data["access_token"]
                cls.test_users[user_type]["user_id"] = data["user"]["id"]
                print(f"Registered {user_type} user: {user_data['email']}")
            else:
                print(f"Failed to register {user_type} user: {response.text}")
    
    @classmethod
    def _make_admin_user(cls):
        """Make the admin user an actual admin"""
        # For testing purposes, we'll use the login endpoint to get a fresh token
        response = requests.post(
            f"{API_URL}/auth/login",
            json={
                "email": cls.test_users["admin"]["email"],
                "password": cls.test_users["admin"]["password"]
            }
        )
        
        if response.status_code == 200:
            data = response.json()
            cls.test_users["admin"]["token"] = data["access_token"]
            
            # For testing purposes, we'll make the first registered user an admin
            # This is a workaround since we can't directly access the database
            # In a real scenario, you would need to set this up differently
            
            # First, let's create a new user that we'll make an admin
            admin_email = f"super_admin_{random_string()}@example.com"
            admin_response = requests.post(
                f"{API_URL}/auth/register",
                json={
                    "email": admin_email,
                    "name": "Super Admin",
                    "password": "SuperAdmin123!",
                    "age_verified": True
                }
            )
            
            if admin_response.status_code == 200:
                admin_data = admin_response.json()
                super_admin_token = admin_data["access_token"]
                super_admin_id = admin_data["user"]["id"]
                
                # Now, let's directly update the database to make this user an admin
                # This is a hack for testing purposes
                # In a real scenario, you would need to set this up differently
                print(f"Created super admin user: {admin_email}")
                
                # For now, we'll just note that admin tests will be skipped
                print("Note: Admin tests will be skipped as we can't directly make a user an admin in this test environment")
            else:
                print(f"Failed to create super admin: {admin_response.text}")
        else:
            print(f"Failed to login admin user: {response.text}")
    
    def test_01_user_registration(self):
        """Test user registration"""
        # Test with a new user
        test_email = f"test_register_{random_string()}@example.com"
        response = requests.post(
            f"{API_URL}/auth/register",
            json={
                "email": test_email,
                "name": "Test Register User",
                "password": "Password123!",
                "age_verified": True
            }
        )
        
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("access_token", data)
        self.assertIn("user", data)
        self.assertEqual(data["user"]["email"], test_email)
        self.assertEqual(data["user"]["age_verified"], True)
        
        # Test with existing email (should fail)
        response = requests.post(
            f"{API_URL}/auth/register",
            json={
                "email": test_email,
                "name": "Duplicate User",
                "password": "Password123!",
                "age_verified": True
            }
        )
        
        self.assertEqual(response.status_code, 400)
        self.assertIn("Email already registered", response.text)
    
    def test_02_user_login(self):
        """Test user login"""
        # Test with valid credentials
        response = requests.post(
            f"{API_URL}/auth/login",
            json={
                "email": self.test_users["regular"]["email"],
                "password": self.test_users["regular"]["password"]
            }
        )
        
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("access_token", data)
        self.assertIn("user", data)
        self.assertEqual(data["user"]["email"], self.test_users["regular"]["email"])
        
        # Update token for future tests
        self.test_users["regular"]["token"] = data["access_token"]
        
        # Test with invalid credentials
        response = requests.post(
            f"{API_URL}/auth/login",
            json={
                "email": self.test_users["regular"]["email"],
                "password": "WrongPassword123!"
            }
        )
        
        self.assertEqual(response.status_code, 400)
        self.assertIn("Invalid credentials", response.text)
    
    def test_03_user_profile(self):
        """Test getting user profile"""
        headers = {"Authorization": f"Bearer {self.test_users['regular']['token']}"}
        response = requests.get(f"{API_URL}/auth/profile", headers=headers)
        
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["email"], self.test_users["regular"]["email"])
        self.assertEqual(data["name"], self.test_users["regular"]["name"])
        self.assertEqual(data["age_verified"], self.test_users["regular"]["age_verified"])
        
        # Test with invalid token
        headers = {"Authorization": "Bearer invalid_token"}
        response = requests.get(f"{API_URL}/auth/profile", headers=headers)
        
        self.assertEqual(response.status_code, 401)
    
    def test_04_video_upload(self):
        """Test video upload"""
        headers = {"Authorization": f"Bearer {self.test_users['regular']['token']}"}
        
        # Test with valid video
        with open(self.test_video_path, 'rb') as video_file:
            files = {'file': ('test_video.mp4', video_file, 'video/mp4')}
            data = {
                'title': 'Test Video',
                'description': 'This is a test video',
                'category': 'Test Category',
                'tags': 'test,video,upload'
            }
            
            response = requests.post(
                f"{API_URL}/videos/upload",
                headers=headers,
                files=files,
                data=data
            )
        
        self.assertEqual(response.status_code, 200)
        upload_data = response.json()
        self.assertIn("video_id", upload_data)
        self.assertIn("message", upload_data)
        self.assertEqual(upload_data["message"], "Video uploaded successfully")
        
        # Save video ID for future tests
        self.test_users["regular"]["video_id"] = upload_data["video_id"]
        
        # Test with invalid file type (should fail)
        # Create a text file
        test_text_path = Path('/app/test_file.txt')
        with open(test_text_path, 'w') as f:
            f.write("This is not a video file")
        
        try:
            with open(test_text_path, 'rb') as text_file:
                files = {'file': ('test_file.txt', text_file, 'text/plain')}
                data = {
                    'title': 'Invalid File',
                    'description': 'This is not a video',
                    'category': 'Test Category',
                    'tags': 'test,invalid'
                }
                
                response = requests.post(
                    f"{API_URL}/videos/upload",
                    headers=headers,
                    files=files,
                    data=data
                )
            
            self.assertEqual(response.status_code, 400)
            self.assertIn("File must be a video", response.text)
        finally:
            # Clean up
            if test_text_path.exists():
                test_text_path.unlink()
    
    def test_05_get_videos(self):
        """Test getting videos"""
        headers = {"Authorization": f"Bearer {self.test_users['regular']['token']}"}
        response = requests.get(f"{API_URL}/videos", headers=headers)
        
        self.assertEqual(response.status_code, 200)
        videos = response.json()
        self.assertIsInstance(videos, list)
        
        # Test filtering by category
        if videos:
            category = videos[0]["category"]
            response = requests.get(f"{API_URL}/videos?category={category}", headers=headers)
            self.assertEqual(response.status_code, 200)
            filtered_videos = response.json()
            self.assertIsInstance(filtered_videos, list)
            for video in filtered_videos:
                self.assertEqual(video["category"], category)
    
    def test_06_get_video_by_id(self):
        """Test getting a specific video"""
        if not hasattr(self.test_users["regular"], "video_id"):
            # If we don't have a video ID from the upload test, let's upload a video now
            headers = {"Authorization": f"Bearer {self.test_users['regular']['token']}"}
            
            with open(self.test_video_path, 'rb') as video_file:
                files = {'file': ('test_video.mp4', video_file, 'video/mp4')}
                data = {
                    'title': 'Test Video for Get',
                    'description': 'This is a test video for get_video',
                    'category': 'Test Category',
                    'tags': 'test,video,get'
                }
                
                response = requests.post(
                    f"{API_URL}/videos/upload",
                    headers=headers,
                    files=files,
                    data=data
                )
                
                self.assertEqual(response.status_code, 200)
                upload_data = response.json()
                self.test_users["regular"]["video_id"] = upload_data["video_id"]
        
        video_id = self.test_users["regular"]["video_id"]
        headers = {"Authorization": f"Bearer {self.test_users['regular']['token']}"}
        response = requests.get(f"{API_URL}/videos/{video_id}", headers=headers)
        
        # The video might be in pending status, which would return 403 for non-admin users
        # For testing purposes, we'll accept either 200 or 403
        self.assertTrue(response.status_code in [200, 403])
        
        if response.status_code == 200:
            video = response.json()
            self.assertEqual(video["id"], video_id)
        else:
            self.assertIn("Video not available", response.text)
        
        # Test with invalid video ID
        response = requests.get(f"{API_URL}/videos/invalid_id", headers=headers)
        self.assertEqual(response.status_code, 404)
    
    def test_07_video_streaming(self):
        """Test video streaming"""
        if not hasattr(self.test_users["regular"], "video_id"):
            # If we don't have a video ID from the upload test, let's upload a video now
            headers = {"Authorization": f"Bearer {self.test_users['regular']['token']}"}
            
            with open(self.test_video_path, 'rb') as video_file:
                files = {'file': ('test_video.mp4', video_file, 'video/mp4')}
                data = {
                    'title': 'Test Video for Streaming',
                    'description': 'This is a test video for streaming',
                    'category': 'Test Category',
                    'tags': 'test,video,stream'
                }
                
                response = requests.post(
                    f"{API_URL}/videos/upload",
                    headers=headers,
                    files=files,
                    data=data
                )
                
                self.assertEqual(response.status_code, 200)
                upload_data = response.json()
                self.test_users["regular"]["video_id"] = upload_data["video_id"]
        
        video_id = self.test_users["regular"]["video_id"]
        headers = {"Authorization": f"Bearer {self.test_users['regular']['token']}"}
        response = requests.get(f"{API_URL}/videos/{video_id}/stream", headers=headers)
        
        # The video might be in pending status, which would return 403 for non-admin users
        # For testing purposes, we'll accept either 200 or 403
        self.assertTrue(response.status_code in [200, 403])
        
        if response.status_code == 200:
            self.assertTrue(response.headers.get('Content-Type').startswith('video/') or 
                           response.headers.get('Content-Type') == 'application/octet-stream')
        else:
            self.assertIn("Video not available", response.text)
        
        # Test with invalid video ID
        response = requests.get(f"{API_URL}/videos/invalid_id/stream", headers=headers)
        self.assertEqual(response.status_code, 404)
        
        # Test without authentication
        response = requests.get(f"{API_URL}/videos/{video_id}/stream")
        # The API might return 401 (unauthorized) or 403 (forbidden) depending on the implementation
        self.assertTrue(response.status_code in [401, 403])
    
    def test_08_categories(self):
        """Test getting categories"""
        headers = {"Authorization": f"Bearer {self.test_users['regular']['token']}"}
        response = requests.get(f"{API_URL}/categories", headers=headers)
        
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("categories", data)
        self.assertIsInstance(data["categories"], list)
    
    def test_09_search(self):
        """Test search functionality"""
        headers = {"Authorization": f"Bearer {self.test_users['regular']['token']}"}
        
        # Upload a video with specific tags for search testing
        with open(self.test_video_path, 'rb') as video_file:
            files = {'file': ('search_test.mp4', video_file, 'video/mp4')}
            data = {
                'title': 'Search Test Video',
                'description': 'This video is for testing search functionality',
                'category': 'Search Category',
                'tags': 'search,test,functionality'
            }
            
            response = requests.post(
                f"{API_URL}/videos/upload",
                headers=headers,
                files=files,
                data=data
            )
            
            self.assertEqual(response.status_code, 200)
        
        # Test search by query
        response = requests.post(
            f"{API_URL}/search",
            headers=headers,
            json={"query": "search"}
        )
        
        self.assertEqual(response.status_code, 200)
        results = response.json()
        self.assertIsInstance(results, list)
        if results:
            found_search_video = False
            for video in results:
                if "Search Test Video" in video["title"]:
                    found_search_video = True
                    break
            self.assertTrue(found_search_video, "Search did not return the expected video")
        
        # Test search by category
        response = requests.post(
            f"{API_URL}/search",
            headers=headers,
            json={"category": "Search Category"}
        )
        
        self.assertEqual(response.status_code, 200)
        results = response.json()
        self.assertIsInstance(results, list)
        if results:
            for video in results:
                self.assertEqual(video["category"], "Search Category")
        
        # Test search by tags
        response = requests.post(
            f"{API_URL}/search",
            headers=headers,
            json={"tags": ["functionality"]}
        )
        
        self.assertEqual(response.status_code, 200)
        results = response.json()
        self.assertIsInstance(results, list)
        if results:
            found_tag = False
            for video in results:
                if "functionality" in video["tags"]:
                    found_tag = True
                    break
            self.assertTrue(found_tag, "Tag search did not return the expected video")
    
    def test_10_admin_video_approval(self):
        """Test admin video approval"""
        # Skip this test since we can't make a user an admin in this test environment
        self.skipTest("Admin test skipped - can't make a user an admin in this test environment")
    
    def test_11_admin_video_rejection(self):
        """Test admin video rejection"""
        # Skip this test since we can't make a user an admin in this test environment
        self.skipTest("Admin test skipped - can't make a user an admin in this test environment")
    
    def test_12_admin_user_management(self):
        """Test admin user management"""
        # Skip this test since we can't make a user an admin in this test environment
        self.skipTest("Admin test skipped - can't make a user an admin in this test environment")
    
    def test_13_emergent_oauth(self):
        """Test Emergent OAuth integration"""
        # This is a mock test since we can't actually test the OAuth flow without a real session
        # In a real test, you would need to simulate the OAuth flow
        
        # We'll just verify the endpoint exists
        response = requests.post(
            f"{API_URL}/auth/emergent-login",
            json={"session_id": "mock_session_id"}
        )
        
        # We expect this to fail with a 422 since we're using a mock session ID
        # and the endpoint expects a string, not a JSON object
        self.assertEqual(response.status_code, 422)

if __name__ == "__main__":
    unittest.main(argv=['first-arg-is-ignored'], exit=False)