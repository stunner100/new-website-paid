#!/bin/bash

# Test user setup script for R2 upload testing
BASE_URL="http://localhost:9999/.netlify/functions"
TEST_EMAIL="testuser@example.com"
TEST_PASSWORD="testpass123"

echo "🔧 Setting up test user for R2 upload testing..."

# 1. Register test user
echo "📝 Registering test user..."
REGISTER_RESPONSE=$(curl -s -X POST "$BASE_URL/api/auth/register" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$TEST_EMAIL\",\"name\":\"Test User\",\"password\":\"$TEST_PASSWORD\",\"age_verified\":true}")

echo "Register response: $REGISTER_RESPONSE"

# 2. Login to get JWT token
echo "🔑 Logging in..."
LOGIN_RESPONSE=$(curl -s -X POST "$BASE_URL/api/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$TEST_EMAIL\",\"password\":\"$TEST_PASSWORD\"}")

echo "Login response: $LOGIN_RESPONSE"

# Extract token from response
TOKEN=$(echo "$LOGIN_RESPONSE" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)

if [ -z "$TOKEN" ]; then
    echo "❌ Failed to get token from login response"
    exit 1
fi

echo "✅ Got token: ${TOKEN:0:20}..."

# 3. Elevate user to admin
echo "👑 Elevating user to admin..."
ADMIN_RESPONSE=$(curl -s -X POST "$BASE_URL/api/dev/make-admin" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN")

echo "Admin elevation response: $ADMIN_RESPONSE"

echo ""
echo "🎉 Test user setup complete!"
echo "📧 Email: $TEST_EMAIL"
echo "🔑 Password: $TEST_PASSWORD"
echo "🎫 Token: $TOKEN"
echo ""
echo "You can now use these credentials to test the upload in the UI:"
echo "1. Go to http://localhost:3000"
echo "2. Login with the above credentials"
echo "3. Try uploading a video file"