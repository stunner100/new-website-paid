import React, { useState, useEffect, createContext, useContext } from 'react';
import './App.css';
import axios from 'axios';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

// Auth Context
const AuthContext = createContext();

const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(localStorage.getItem('token'));
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (token) {
      axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
      fetchProfile();
    } else {
      setLoading(false);
    }
  }, [token]);

  const fetchProfile = async () => {
    try {
      const response = await axios.get(`${API}/auth/profile`);
      setUser(response.data);
    } catch (error) {
      console.error('Failed to fetch profile:', error);
      logout();
    } finally {
      setLoading(false);
    }
  };

  const login = (token, userData) => {
    localStorage.setItem('token', token);
    setToken(token);
    setUser(userData);
    axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
  };

  const logout = () => {
    localStorage.removeItem('token');
    setToken(null);
    setUser(null);
    delete axios.defaults.headers.common['Authorization'];
  };

  return (
    <AuthContext.Provider value={{ user, login, logout, loading }}>
      {children}
    </AuthContext.Provider>
  );
};

const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

// Age Verification Modal
const AgeVerificationModal = ({ isOpen, onVerify, onCancel }) => {
  if (!isOpen) return null;

  return (
    <div className="modal-overlay">
      <div className="modal-content">
        <h2>Age Verification Required</h2>
        <p>You must be 18 or older to access this content.</p>
        <p>By clicking "I am 18+", you confirm that you are of legal age to view adult content.</p>
        <div className="modal-actions">
          <button onClick={onVerify} className="btn btn-primary">I am 18+</button>
          <button onClick={onCancel} className="btn btn-secondary">Cancel</button>
        </div>
      </div>
    </div>
  );
};

// Auth Forms
const AuthForms = () => {
  const [isLogin, setIsLogin] = useState(true);
  const [formData, setFormData] = useState({
    email: '',
    password: '',
    name: '',
    age_verified: false
  });
  const [showAgeVerification, setShowAgeVerification] = useState(false);
  const [error, setError] = useState('');
  const { login } = useAuth();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    if (!isLogin && !formData.age_verified) {
      setShowAgeVerification(true);
      return;
    }

    try {
      const endpoint = isLogin ? '/auth/login' : '/auth/register';
      const response = await axios.post(`${API}${endpoint}`, formData);
      
      login(response.data.access_token, response.data.user);
    } catch (error) {
      setError(error.response?.data?.detail || 'Authentication failed');
    }
  };

  const handleAgeVerification = (verified) => {
    setShowAgeVerification(false);
    if (verified) {
      setFormData({ ...formData, age_verified: true });
    }
  };

  const handleEmergentLogin = () => {
    const redirectUrl = window.location.origin + '/auth/callback';
    window.location.href = `https://auth.emergentagent.com/?redirect=${encodeURIComponent(redirectUrl)}`;
  };

  return (
    <div className="auth-container">
      <div className="auth-card">
        <h2>{isLogin ? 'Sign In' : 'Create Account'}</h2>
        
        {error && <div className="error-message">{error}</div>}
        
        <form onSubmit={handleSubmit}>
          {!isLogin && (
            <input
              type="text"
              placeholder="Full Name"
              value={formData.name}
              onChange={(e) => setFormData({ ...formData, name: e.target.value })}
              required
            />
          )}
          <input
            type="email"
            placeholder="Email"
            value={formData.email}
            onChange={(e) => setFormData({ ...formData, email: e.target.value })}
            required
          />
          <input
            type="password"
            placeholder="Password"
            value={formData.password}
            onChange={(e) => setFormData({ ...formData, password: e.target.value })}
            required
          />
          <button type="submit" className="btn btn-primary">
            {isLogin ? 'Sign In' : 'Create Account'}
          </button>
        </form>

        <div className="auth-divider">
          <span>or</span>
        </div>

        <button onClick={handleEmergentLogin} className="btn btn-google">
          Continue with Google
        </button>

        <p className="auth-switch">
          {isLogin ? "Don't have an account?" : "Already have an account?"}
          <button onClick={() => setIsLogin(!isLogin)} className="link-button">
            {isLogin ? 'Sign Up' : 'Sign In'}
          </button>
        </p>
      </div>

      <AgeVerificationModal
        isOpen={showAgeVerification}
        onVerify={() => handleAgeVerification(true)}
        onCancel={() => handleAgeVerification(false)}
      />
    </div>
  );
};

// Video Player Component
const VideoPlayer = ({ videoId, onClose }) => {
  const [videoUrl, setVideoUrl] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const url = `${API}/videos/${videoId}/stream`;
    setVideoUrl(url);
    setLoading(false);
  }, [videoId]);

  return (
    <div className="video-player-modal">
      <div className="video-player-content">
        <button className="close-button" onClick={onClose}>×</button>
        {loading ? (
          <div className="loading">Loading video...</div>
        ) : (
          <video controls autoPlay className="video-player">
            <source src={videoUrl} type="video/mp4" />
            Your browser does not support the video tag.
          </video>
        )}
      </div>
    </div>
  );
};

// Video Card Component
const VideoCard = ({ video, onPlay }) => {
  return (
    <div className="video-card" onClick={() => onPlay(video.id)}>
      <div className="video-thumbnail">
        <img 
          src="https://images.unsplash.com/photo-1489599849927-2ee91cede3ba?w=300&h=200&fit=crop" 
          alt={video.title}
        />
        <div className="play-overlay">
          <div className="play-button">▶</div>
        </div>
      </div>
      <div className="video-info">
        <h3>{video.title}</h3>
        <p>{video.description}</p>
        <div className="video-meta">
          <span className="category">{video.category}</span>
          <span className="views">{video.views} views</span>
        </div>
        <div className="video-tags">
          {video.tags.map(tag => (
            <span key={tag} className="tag">{tag}</span>
          ))}
        </div>
      </div>
    </div>
  );
};

// Upload Form Component
const UploadForm = ({ onClose, onSuccess }) => {
  const [formData, setFormData] = useState({
    title: '',
    description: '',
    category: '',
    tags: ''
  });
  const [file, setFile] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!file) {
      setError('Please select a video file');
      return;
    }

    setUploading(true);
    setError('');

    const uploadData = new FormData();
    uploadData.append('title', formData.title);
    uploadData.append('description', formData.description);
    uploadData.append('category', formData.category);
    uploadData.append('tags', formData.tags);
    uploadData.append('file', file);

    try {
      await axios.post(`${API}/videos/upload`, uploadData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });
      onSuccess();
    } catch (error) {
      setError(error.response?.data?.detail || 'Upload failed');
    } finally {
      setUploading(false);
    }
  };

  return (
    <div className="modal-overlay">
      <div className="modal-content upload-modal">
        <h2>Upload Video</h2>
        {error && <div className="error-message">{error}</div>}
        
        <form onSubmit={handleSubmit}>
          <input
            type="text"
            placeholder="Video Title"
            value={formData.title}
            onChange={(e) => setFormData({ ...formData, title: e.target.value })}
            required
          />
          <textarea
            placeholder="Video Description"
            value={formData.description}
            onChange={(e) => setFormData({ ...formData, description: e.target.value })}
            rows="4"
            required
          />
          <input
            type="text"
            placeholder="Category"
            value={formData.category}
            onChange={(e) => setFormData({ ...formData, category: e.target.value })}
            required
          />
          <input
            type="text"
            placeholder="Tags (comma separated)"
            value={formData.tags}
            onChange={(e) => setFormData({ ...formData, tags: e.target.value })}
          />
          <input
            type="file"
            accept="video/*"
            onChange={(e) => setFile(e.target.files[0])}
            required
          />
          
          <div className="modal-actions">
            <button type="submit" disabled={uploading} className="btn btn-primary">
              {uploading ? 'Uploading...' : 'Upload Video'}
            </button>
            <button type="button" onClick={onClose} className="btn btn-secondary">
              Cancel
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

// Main App Component
const MainApp = () => {
  const { user, logout } = useAuth();
  const [videos, setVideos] = useState([]);
  const [categories, setCategories] = useState([]);
  const [selectedCategory, setSelectedCategory] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [currentVideo, setCurrentVideo] = useState(null);
  const [showUpload, setShowUpload] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchVideos();
    fetchCategories();
  }, [selectedCategory]);

  const fetchVideos = async () => {
    try {
      const params = selectedCategory ? { category: selectedCategory } : {};
      const response = await axios.get(`${API}/videos`, { params });
      setVideos(response.data);
    } catch (error) {
      console.error('Failed to fetch videos:', error);
    } finally {
      setLoading(false);
    }
  };

  const fetchCategories = async () => {
    try {
      const response = await axios.get(`${API}/categories`);
      setCategories(response.data.categories);
    } catch (error) {
      console.error('Failed to fetch categories:', error);
    }
  };

  const handleSearch = async () => {
    if (!searchQuery.trim()) {
      fetchVideos();
      return;
    }

    try {
      const response = await axios.post(`${API}/search`, {
        query: searchQuery,
        category: selectedCategory || null
      });
      setVideos(response.data);
    } catch (error) {
      console.error('Search failed:', error);
    }
  };

  const handleUploadSuccess = () => {
    setShowUpload(false);
    fetchVideos();
  };

  if (loading) {
    return <div className="loading">Loading...</div>;
  }

  return (
    <div className="app">
      {/* Header */}
      <header className="header">
        <div className="header-content">
          <h1 className="logo">AdultFlix</h1>
          <div className="header-actions">
            {user.is_approved && (
              <button onClick={() => setShowUpload(true)} className="btn btn-primary">
                Upload Video
              </button>
            )}
            <div className="user-menu">
              <span>Welcome, {user.name}</span>
              <button onClick={logout} className="btn btn-secondary">Logout</button>
            </div>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <section className="hero">
        <div className="hero-content">
          <h2>Premium Adult Entertainment</h2>
          <p>Stream high-quality content in a safe, secure environment</p>
        </div>
        <div className="hero-image">
          <img src="https://images.unsplash.com/photo-1717295248358-4b8f2c8989d6?w=1200&h=400&fit=crop" alt="Premium streaming" />
        </div>
      </section>

      {/* Search and Filter */}
      <section className="search-section">
        <div className="search-container">
          <div className="search-bar">
            <input
              type="text"
              placeholder="Search videos..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              onKeyPress={(e) => e.key === 'Enter' && handleSearch()}
            />
            <button onClick={handleSearch} className="btn btn-primary">Search</button>
          </div>
          <div className="filter-bar">
            <select 
              value={selectedCategory} 
              onChange={(e) => setSelectedCategory(e.target.value)}
            >
              <option value="">All Categories</option>
              {categories.map(category => (
                <option key={category} value={category}>{category}</option>
              ))}
            </select>
          </div>
        </div>
      </section>

      {/* Video Grid */}
      <section className="video-grid">
        {videos.length === 0 ? (
          <div className="no-videos">
            <h3>No videos found</h3>
            <p>Try adjusting your search or filters</p>
          </div>
        ) : (
          <div className="videos-container">
            {videos.map(video => (
              <VideoCard
                key={video.id}
                video={video}
                onPlay={setCurrentVideo}
              />
            ))}
          </div>
        )}
      </section>

      {/* Modals */}
      {currentVideo && (
        <VideoPlayer
          videoId={currentVideo}
          onClose={() => setCurrentVideo(null)}
        />
      )}

      {showUpload && (
        <UploadForm
          onClose={() => setShowUpload(false)}
          onSuccess={handleUploadSuccess}
        />
      )}
    </div>
  );
};

// Auth Callback Component
const AuthCallback = () => {
  const { login } = useAuth();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    const handleCallback = async () => {
      try {
        // Parse session ID from URL fragment
        const hash = window.location.hash.substring(1);
        const params = new URLSearchParams(hash);
        const sessionId = params.get('session_id');

        if (!sessionId) {
          setError('No session ID found');
          return;
        }

        // Exchange session ID for user data
        const response = await axios.post(`${API}/auth/emergent-login`, sessionId, {
          headers: {
            'Content-Type': 'application/json',
          },
        });

        login(response.data.access_token, response.data.user);
      } catch (error) {
        setError(error.response?.data?.detail || 'Authentication failed');
      } finally {
        setLoading(false);
      }
    };

    handleCallback();
  }, [login]);

  if (loading) {
    return <div className="loading">Completing authentication...</div>;
  }

  if (error) {
    return (
      <div className="error-container">
        <h2>Authentication Error</h2>
        <p>{error}</p>
        <button onClick={() => window.location.href = '/'} className="btn btn-primary">
          Go Home
        </button>
      </div>
    );
  }

  return null;
};

// Main App Router
const App = () => {
  return (
    <AuthProvider>
      <AppRouter />
    </AuthProvider>
  );
};

const AppRouter = () => {
  const { user, loading } = useAuth();
  const [showApprovalMessage, setShowApprovalMessage] = useState(false);

  useEffect(() => {
    if (user && !user.is_approved) {
      setShowApprovalMessage(true);
    }
  }, [user]);

  if (loading) {
    return <div className="loading">Loading...</div>;
  }

  // Handle auth callback
  if (window.location.pathname === '/auth/callback') {
    return <AuthCallback />;
  }

  if (!user) {
    return <AuthForms />;
  }

  if (!user.age_verified) {
    return (
      <div className="error-container">
        <h2>Age Verification Required</h2>
        <p>You must verify your age to access this content.</p>
      </div>
    );
  }

  return (
    <>
      <MainApp />
      {showApprovalMessage && !user.is_approved && (
        <div className="approval-banner">
          <p>Your account is pending approval. You can view content but cannot upload videos yet.</p>
          <button onClick={() => setShowApprovalMessage(false)}>×</button>
        </div>
      )}
    </>
  );
};

export default App;