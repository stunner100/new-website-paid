#!/usr/bin/env python3
import os
import asyncio
from pathlib import Path
from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorClient

# Load backend .env
BACKEND_DIR = Path(__file__).resolve().parents[1]
load_dotenv(BACKEND_DIR / '.env')

async def main():
    mongo_url = os.environ['MONGO_URL']
    db_name = os.environ['DB_NAME']
    client = AsyncIOMotorClient(mongo_url)
    db = client[db_name]

    count_before = await db.users.count_documents({})
    result = await db.users.delete_many({})
    count_after = await db.users.count_documents({})

    print(f"Users before: {count_before}")
    print(f"Deleted count: {result.deleted_count}")
    print(f"Users after: {count_after}")

    client.close()

if __name__ == '__main__':
    asyncio.run(main())