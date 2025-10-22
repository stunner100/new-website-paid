from fastapi import FastAPI, APIRouter, HTTPException, Depends, File, UploadFile, Form, Request, BackgroundTasks
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
# from starlette.middleware.sessions import SessionMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Optional
import uuid
from datetime import datetime, timedelta
import hashlib
import jwt
import aiofiles
import mimetypes
from authlib.integrations.starlette_client import OAuth
import httpx
import shutil
import re

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# JWT Secret
JWT_SECRET = os.environ.get('JWT_SECRET', 'your-secret-key-here')

# Create uploads directory
uploads_dir = (ROOT_DIR.parent / "uploads")
uploads_dir.mkdir(parents=True, exist_ok=True)

# Create the main app
app = FastAPI(title="Adult Content Platform API")

# Add session middleware
# app.add_middleware(SessionMiddleware, secret_key=JWT_SECRET)

# OAuth setup
oauth = OAuth()

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Security
security = HTTPBearer()
security_optional = HTTPBearer(auto_error=False)

# Models
class User(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    email: str
    name: str
    password_hash: Optional[str] = None
    age_verified: bool = False
    is_admin: bool = False
    is_approved: bool = False
    created_at: datetime = Field(default_factory=datetime.utcnow)
    picture: Optional[str] = None
    session_token: Optional[str] = None

class UserRegister(BaseModel):
    email: str
    name: str
    password: str
    age_verified: bool

class UserLogin(BaseModel):
    email: str
    password: str

class Video(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    description: str
    category: str
    tags: List[str] = []
    filename: str
    file_path: str
    file_size: int
    duration: Optional[int] = None
    thumbnail: Optional[str] = None
    uploaded_by: str
    status: str = "pending"  # pending, approved, rejected
    created_at: datetime = Field(default_factory=datetime.utcnow)
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    views: int = 0

class VideoUpload(BaseModel):
    title: str
    description: str
    category: str
    tags: List[str] = []

class VideoSearch(BaseModel):
    query: Optional[str] = None
    category: Optional[str] = None
    tags: Optional[List[str]] = None
    status: Optional[str] = None

# Utility functions
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password: str, hashed: str) -> bool:
    return hash_password(password) == hashed

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=7)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm="HS256")
    return encoded_jwt

def verify_token(token: str):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def _normalize_whitespace(s: str) -> str:
    return re.sub(r"\s+", " ", s or "").strip()

def normalize_category(category: str) -> str:
    # Trim, collapse whitespace, and Title-Case for display consistency
    c = _normalize_whitespace(category)
    return c.title() if c else c

def normalize_tag(tag: str) -> str:
    # Trim/collapse whitespace and lowercase for consistent matching
    return _normalize_whitespace(tag).lower()

def dedupe_preserve_order(items: List[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for it in items:
        if it not in seen:
            seen.add(it)
            out.append(it)
    return out

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    payload = verify_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    user = await db.users.find_one({"id": payload["sub"]})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    
    return User(**user)

async def get_admin_user(current_user: User = Depends(get_current_user)):
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user

# Routes
@api_router.post("/auth/register")
async def register(user_data: UserRegister):
    # Check if user exists
    existing_user = await db.users.find_one({"email": user_data.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create user
    users_count = await db.users.count_documents({})
    is_first_user = users_count == 0
    user = User(
        email=user_data.email,
        name=user_data.name,
        password_hash=hash_password(user_data.password),
        age_verified=user_data.age_verified,
        is_admin=is_first_user,
        is_approved=is_first_user
    )
    
    await db.users.insert_one(user.dict())
    
    # Create token
    access_token = create_access_token({"sub": user.id})
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "email": user.email,
            "name": user.name,
            "age_verified": user.age_verified,
            "is_admin": user.is_admin
        }
    }

@api_router.post("/auth/login")
async def login(user_data: UserLogin):
    # Find user
    user = await db.users.find_one({"email": user_data.email})
    if not user or not verify_password(user_data.password, user["password_hash"]):
        raise HTTPException(status_code=400, detail="Invalid credentials")
    
    user_obj = User(**user)
    
    # Create token
    access_token = create_access_token({"sub": user_obj.id})
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "id": user_obj.id,
            "email": user_obj.email,
            "name": user_obj.name,
            "age_verified": user_obj.age_verified,
            "is_admin": user_obj.is_admin
        }
    }

@api_router.get("/auth/profile")
async def get_profile(current_user: User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "email": current_user.email,
        "name": current_user.name,
        "age_verified": current_user.age_verified,
        "is_admin": current_user.is_admin,
        "is_approved": current_user.is_approved
    }

@api_router.post("/auth/emergent-login")
async def emergent_login(session_id: str):
    # Call Emergent auth API
    headers = {"X-Session-ID": session_id}
    async with httpx.AsyncClient() as client:
        response = await client.get(
            "https://demobackend.emergentagent.com/auth/v1/env/oauth/session-data",
            headers=headers
        )
        
        if response.status_code != 200:
            raise HTTPException(status_code=400, detail="Invalid session")
        
        user_data = response.json()
    
    # Check if user exists
    existing_user = await db.users.find_one({"email": user_data["email"]})
    
    if not existing_user:
        # Create new user
        users_count = await db.users.count_documents({})
        is_first_user = users_count == 0
        user = User(
            email=user_data["email"],
            name=user_data["name"],
            picture=user_data.get("picture"),
            age_verified=True,  # Assume age verified through Emergent
            session_token=user_data["session_token"],
            is_admin=is_first_user,
            is_approved=is_first_user
        )
        await db.users.insert_one(user.dict())
    else:
        user = User(**existing_user)
    
    # Create access token
    access_token = create_access_token({"sub": user.id})
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "email": user.email,
            "name": user.name,
            "age_verified": user.age_verified,
            "is_admin": user.is_admin,
            "picture": user.picture
        }
    }

@api_router.post("/videos/upload")
async def upload_video(
    background_tasks: BackgroundTasks,
    title: str = Form(...),
    description: str = Form(...),
    category: str = Form(...),
    tags: str = Form(""),
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user)
):
    # Validate file type
    if not file.content_type.startswith("video/"):
        raise HTTPException(status_code=400, detail="File must be a video")
    
    # Create unique filename
    file_extension = file.filename.split(".")[-1]
    unique_filename = f"{uuid.uuid4()}.{file_extension}"
    file_path = uploads_dir / unique_filename
    
    # Save file
    async with aiofiles.open(file_path, "wb") as buffer:
        content = await file.read()
        await buffer.write(content)
    
    # Normalize category and tags
    category = normalize_category(category)
    tags_list_raw = [t for t in (tags.split(",") if isinstance(tags, str) else [])]
    tags_list = dedupe_preserve_order([normalize_tag(tag) for tag in tags_list_raw if _normalize_whitespace(tag)])
    
    # Create video record
    video = Video(
        title=title,
        description=description,
        category=category,
        tags=tags_list,
        filename=unique_filename,
        file_path=str(file_path),
        file_size=len(content),
        uploaded_by=current_user.id,
        status="approved" if current_user.is_admin else "pending"
    )
    
    await db.videos.insert_one(video.dict())
    
    return {"message": "Video uploaded successfully", "video_id": video.id}

@api_router.get("/videos", response_model=List[Video])
async def get_videos(
    category: Optional[str] = None,
    status: Optional[str] = None,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_optional)
):
    query = {}
    # Default: anonymous users see only approved videos
    is_admin = False
    if credentials and credentials.scheme.lower() == "bearer":
        payload = verify_token(credentials.credentials)
        if payload:
            user = await db.users.find_one({"id": payload["sub"]})
            if user:
                is_admin = bool(user.get("is_admin"))

    if not is_admin:
        query["status"] = "approved"
    elif status:
        query["status"] = status

    if category:
        # Case-insensitive exact match for category to handle mixed-case values
        cat = _normalize_whitespace(category)
        query["category"] = {"$regex": f"^{re.escape(cat)}$", "$options": "i"}

    videos = await db.videos.find(query).sort("created_at", -1).to_list(100)
    return [Video(**video) for video in videos]

@api_router.get("/videos/{video_id}")
async def get_video(video_id: str, credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_optional)):
    video = await db.videos.find_one({"id": video_id})
    if not video:
        raise HTTPException(status_code=404, detail="Video not found")
    
    video_obj = Video(**video)
    
    # Check permissions
    is_admin = False
    if credentials and credentials.scheme.lower() == "bearer":
        payload = verify_token(credentials.credentials)
        if payload:
            user = await db.users.find_one({"id": payload["sub"]})
            if user:
                is_admin = bool(user.get("is_admin"))
    if not is_admin and video_obj.status != "approved":
        raise HTTPException(status_code=403, detail="Video not available")
    
    return video_obj

@api_router.get("/videos/{video_id}/stream")
async def stream_video(video_id: str, request: Request, token: Optional[str] = None, credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_optional)):
    # Resolve optional user from either query token or Authorization header
    current_user: Optional[User] = None
    if token:
        payload = verify_token(token)
        if payload:
            user = await db.users.find_one({"id": payload["sub"]})
            if user:
                current_user = User(**user)
    elif credentials and credentials.scheme.lower() == "bearer":
        payload = verify_token(credentials.credentials)
        if payload:
            user = await db.users.find_one({"id": payload["sub"]})
            if user:
                current_user = User(**user)

    video = await db.videos.find_one({"id": video_id})
    if not video:
        raise HTTPException(status_code=404, detail="Video not found")
    
    video_obj = Video(**video)
    
    # Check permissions
    if not (current_user and current_user.is_admin) and video_obj.status != "approved":
        raise HTTPException(status_code=403, detail="Video not available")
    
    # Increment views
    await db.videos.update_one(
        {"id": video_id},
        {"$inc": {"views": 1}}
    )
    
    # Stream file with Range support
    file_path = Path(video_obj.file_path)
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Video file not found")

    file_size = file_path.stat().st_size
    media_type = mimetypes.guess_type(str(file_path))[0] or "application/octet-stream"

    range_header = request.headers.get("range") or request.headers.get("Range")
    if range_header:
        # Expected format: bytes=start-end
        match = re.match(r"bytes=(\d+)-(\d*)", range_header)
        if not match:
            raise HTTPException(status_code=416, detail="Invalid Range header")
        start = int(match.group(1))
        end = int(match.group(2)) if match.group(2) else file_size - 1
        end = min(end, file_size - 1)
        if start > end or start >= file_size:
            raise HTTPException(status_code=416, detail="Requested Range Not Satisfiable")
        chunk_size = 1024 * 1024  # 1MB
        length = end - start + 1

        def range_iter(fp: Path, start_pos: int, end_pos: int):
            with open(fp, "rb") as f:
                f.seek(start_pos)
                bytes_remaining = length
                while bytes_remaining > 0:
                    read_size = min(chunk_size, bytes_remaining)
                    data = f.read(read_size)
                    if not data:
                        break
                    bytes_remaining -= len(data)
                    yield data

        headers = {
            "Content-Range": f"bytes {start}-{end}/{file_size}",
            "Accept-Ranges": "bytes",
            "Content-Length": str(length),
            "Content-Type": media_type,
            "Content-Disposition": f"inline; filename={video_obj.filename}"
        }
        return StreamingResponse(range_iter(file_path, start, end), status_code=206, headers=headers)
    else:
        def iterfile(fp: Path):
            with open(fp, "rb") as file_like:
                yield from file_like
        headers = {
            "Accept-Ranges": "bytes",
            "Content-Length": str(file_size),
            "Content-Disposition": f"inline; filename={video_obj.filename}"
        }
        return StreamingResponse(
            iterfile(file_path),
            media_type=media_type,
            headers=headers
        )

@api_router.post("/videos/{video_id}/approve")
async def approve_video(video_id: str, admin_user: User = Depends(get_admin_user)):
    result = await db.videos.update_one(
        {"id": video_id},
        {
            "$set": {
                "status": "approved",
                "approved_by": admin_user.id,
                "approved_at": datetime.utcnow()
            }
        }
    )
    
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Video not found")
    
    return {"message": "Video approved successfully"}

@api_router.post("/videos/{video_id}/reject")
async def reject_video(video_id: str, admin_user: User = Depends(get_admin_user)):
    result = await db.videos.update_one(
        {"id": video_id},
        {
            "$set": {
                "status": "rejected",
                "approved_by": admin_user.id,
                "approved_at": datetime.utcnow()
            }
        }
    )
    
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Video not found")
    
    return {"message": "Video rejected successfully"}

@api_router.get("/categories")
async def get_categories():
    cats = await db.videos.distinct("category")
    # Normalize, dedupe, and sort for stable UI
    norm = [normalize_category(c) for c in cats if isinstance(c, str) and _normalize_whitespace(c)]
    uniq = dedupe_preserve_order([c for c in norm if c])
    uniq_sorted = sorted(uniq, key=lambda s: s.lower())
    return {"categories": uniq_sorted}

@api_router.post("/search")
async def search_videos(search_data: VideoSearch, credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_optional)):
    query = {}

    # Determine admin from optional credentials
    is_admin = False
    if credentials and credentials.scheme.lower() == "bearer":
        payload = verify_token(credentials.credentials)
        if payload:
            user = await db.users.find_one({"id": payload["sub"]})
            if user:
                is_admin = bool(user.get("is_admin"))

    # Regular/anonymous users can only see approved videos
    if not is_admin:
        query["status"] = "approved"
    elif search_data.status:
        query["status"] = search_data.status

    if search_data.category:
        cat = _normalize_whitespace(search_data.category)
        query["category"] = {"$regex": f"^{re.escape(cat)}$", "$options": "i"}

    if search_data.tags:
        # Case-insensitive match for any provided tag
        tag_regexes = [{"$regex": f"^{re.escape(normalize_tag(t))}$", "$options": "i"} for t in search_data.tags if t]
        if tag_regexes:
            query["tags"] = {"$in": tag_regexes}

    if search_data.query:
        q = _normalize_whitespace(search_data.query)
        if q:
            query["$or"] = [
                {"title": {"$regex": q, "$options": "i"}},
                {"description": {"$regex": q, "$options": "i"}},
                {"tags": {"$regex": q, "$options": "i"}},
            ]

    videos = await db.videos.find(query).sort("created_at", -1).to_list(100)
    return [Video(**video) for video in videos]

@api_router.get("/admin/users")
async def get_users(admin_user: User = Depends(get_admin_user)):
    users = await db.users.find().to_list(100)
    return [{"id": user["id"], "email": user["email"], "name": user["name"], "is_admin": user["is_admin"], "is_approved": user["is_approved"]} for user in users]

@api_router.post("/admin/users/{user_id}/approve")
async def approve_user(user_id: str, admin_user: User = Depends(get_admin_user)):
    result = await db.users.update_one(
        {"id": user_id},
        {"$set": {"is_approved": True}}
    )
    
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {"message": "User approved successfully"}

@api_router.post("/admin/users/{user_id}/make-admin")
async def make_admin(user_id: str, admin_user: User = Depends(get_admin_user)):
    result = await db.users.update_one(
        {"id": user_id},
        {"$set": {"is_admin": True}}
    )
    
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {"message": "User made admin successfully"}

# Include the router in the main app
@api_router.delete("/videos/{video_id}")
async def delete_video(video_id: str, admin_user: User = Depends(get_admin_user)):
    # Find the video record
    video = await db.videos.find_one({"id": video_id})
    if not video:
        raise HTTPException(status_code=404, detail="Video not found")

    # Attempt to delete the file from disk, only if it resides under uploads_dir
    try:
        file_path = Path(video.get("file_path", ""))
        if file_path and file_path.exists():
            # Ensure path is inside uploads_dir to prevent accidental deletion elsewhere
            if uploads_dir in file_path.parents or file_path == uploads_dir / file_path.name:
                file_path.unlink()
            else:
                logging.warning(f"Refusing to delete file outside uploads dir: {file_path}")
    except Exception as e:
        # Log and continue to delete DB record
        logging.warning(f"Failed to delete file for video {video_id}: {e}")

    # Delete the video document
    await db.videos.delete_one({"id": video_id})
    return {"message": "Video deleted successfully"}

app.include_router(api_router)

# Static files for uploads
app.mount("/uploads", StaticFiles(directory=str(uploads_dir)), name="uploads")

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()