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
  const { token } = useAuth();

  useEffect(() => {
    const t = token || localStorage.getItem('token');
    const url = t
      ? `${API}/videos/${videoId}/stream?token=${encodeURIComponent(t)}`
      : `${API}/videos/${videoId}/stream`;
    setVideoUrl(url);
    setLoading(false);
  }, [videoId, token]);

  return (
    <div className="video-player-modal">
      <div className="video-player-content">
        <button className="close-button" onClick={onClose}>×</button>
        {loading ? (
          <div className="loading">Loading video...</div>
        ) : (
          <video controls autoPlay className="video-player">
            <source src={videoUrl} />
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
const UploadForm = ({ onClose, onSuccess, onNotify }) => {
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
       onNotify && onNotify('Please select a video file', 'error');
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
       onNotify && onNotify('Upload successful', 'success');
       onSuccess();
     } catch (error) {
       setError(error.response?.data?.detail || 'Upload failed');
       onNotify && onNotify(error.response?.data?.detail || 'Upload failed', 'error');
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

// Admin Panel Component
const AdminPanel = ({ onClose }) => {
  const { user } = useAuth();
  const [activeTab, setActiveTab] = useState('videos');
  const [videos, setVideos] = useState([]);
  const [statusFilter, setStatusFilter] = useState('pending');
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [showUploadModal, setShowUploadModal] = useState(false);
  // Toast state for inline notifications within AdminPanel
  const [toast, setToast] = useState({ message: '', type: '' });
  const showToast = (message, type = 'info') => {
    setToast({ message, type });
    // clear previous timer and auto-hide after 3.5s
    if (showToast._t) window.clearTimeout(showToast._t);
    showToast._t = window.setTimeout(() => setToast({ message: '', type: '' }), 3500);
  };

  const loadVideos = async () => {
    setLoading(true);
    setError('');
    try {
      const params = statusFilter === 'all' ? {} : { status: statusFilter };
      const response = await axios.get(`${API}/videos`, { params });
      setVideos(response.data);
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to load videos');
    } finally {
      setLoading(false);
    }
  };

  const loadUsers = async () => {
    setLoading(true);
    setError('');
    try {
      const response = await axios.get(`${API}/admin/users`);
      setUsers(response.data);
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to load users');
    } finally {
      setLoading(false);
    }
  };

  const handleUploadSuccess = async () => {
    setShowUploadModal(false);
    setActiveTab('videos');
    await loadVideos();
  };

  useEffect(() => {
    if (activeTab === 'videos') {
      loadVideos();
    } else if (activeTab === 'users') {
      loadUsers();
    }
  }, [activeTab, statusFilter]);

  // Guard: if Upload tab is somehow active but user isn't approved or admin, redirect to Videos
  useEffect(() => {
    if (activeTab === 'upload' && !user?.is_admin) {
      setActiveTab('videos');
    }
  }, [activeTab, user]);

  const approveVideo = async (id) => {
    try {
      await axios.post(`${API}/videos/${id}/approve`);
      await loadVideos();
      showToast('Video approved successfully', 'success');
    } catch (err) {
      showToast(err.response?.data?.detail || 'Failed to approve video', 'error');
    }
  };

  const rejectVideo = async (id) => {
    try {
      await axios.post(`${API}/videos/${id}/reject`);
      await loadVideos();
      showToast('Video rejected', 'success');
    } catch (err) {
      showToast(err.response?.data?.detail || 'Failed to reject video', 'error');
    }
  };

  const deleteVideo = async (id) => {
    if (!window.confirm('Are you sure you want to delete this video? This action cannot be undone.')) return;
    try {
      await axios.delete(`${API}/videos/${id}`);
      await loadVideos();
      showToast('Video deleted successfully', 'success');
    } catch (err) {
      showToast(err.response?.data?.detail || 'Failed to delete video', 'error');
    }
  };

  const approveUser = async (id) => {
    try {
      await axios.post(`${API}/admin/users/${id}/approve`);
      await loadUsers();
      showToast('User approved successfully', 'success');
    } catch (err) {
      showToast(err.response?.data?.detail || 'Failed to approve user', 'error');
    }
  };

  const makeAdmin = async (id) => {
    try {
      await axios.post(`${API}/admin/users/${id}/make-admin`);
      await loadUsers();
      showToast('User granted admin privileges', 'success');
    } catch (err) {
      showToast(err.response?.data?.detail || 'Failed to make user admin', 'error');
    }
  };

  if (!user?.is_admin) {
    return (
      <div className="error-container">
        <h2>Access Denied</h2>
        <p>You must be an admin to view this page.</p>
        <button onClick={onClose} className="btn btn-primary">Go Back</button>
      </div>
    );
  }

  return (
    <div className="app admin-app">
      <header className="header">
        <div className="header-content">
          <h1 className="logo">Admin Panel</h1>
          <div className="header-actions">
            <button onClick={onClose} className="btn btn-secondary">Back</button>
          </div>
        </div>
      </header>

      <section className="search-section">
        <div className="search-container">
          <div className="filter-bar">
            <div className="admin-tabs">
              <button className={activeTab==='videos'? 'tab active':'tab'} onClick={() => setActiveTab('videos')}>Videos</button>
              {user?.is_admin && (
                <button className={activeTab==='upload'? 'tab active':'tab'} onClick={() => setActiveTab('upload')}>Upload</button>
              )}
              <button className={activeTab==='users'? 'tab active':'tab'} onClick={() => setActiveTab('users')}>Users</button>
            </div>
            {activeTab === 'videos' && (
              <select 
                value={statusFilter} 
                onChange={(e) => setStatusFilter(e.target.value)}
              >
                <option value="pending">Pending</option>
                <option value="approved">Approved</option>
                <option value="rejected">Rejected</option>
                <option value="all">All</option>
              </select>
            )}
          </div>
        </div>
      </section>

      {activeTab === 'videos' ? (
        <section className="video-grid">
          {loading ? (
            <div className="loading">Loading videos...</div>
          ) : error ? (
            <div className="error-message">{error}</div>
          ) : videos.length === 0 ? (
            <div className="no-videos">
              <h3>No videos found</h3>
              <p>Try a different status filter</p>
            </div>
          ) : (
            <div className="videos-container admin-list">
              {videos.map((video) => (
                <div key={video.id} className="video-card admin-card">
                  <div className="video-info">
                    <h3>{video.title}</h3>
                    <p>{video.description}</p>
                    <div className="video-meta">
                      <span className="category">{video.category}</span>
                      <span className="views">{video.views} views</span>
                      <span className="status">Status: {video.status}</span>
                    </div>
                    <div className="video-tags">
                      {(video.tags || []).map(tag => (
                        <span key={tag} className="tag">{tag}</span>
                      ))}
                    </div>
                  </div>
                  <div className="admin-actions">
                    <button 
                      className="btn btn-primary" 
                      onClick={() => approveVideo(video.id)}
                      disabled={video.status === 'approved'}
                    >
                      Approve
                    </button>
                    <button 
                      className="btn btn-secondary" 
                      onClick={() => rejectVideo(video.id)}
                      disabled={video.status === 'rejected'}
                    >
                      Reject
                    </button>
                    <button 
                      className="btn btn-danger" 
                      onClick={() => deleteVideo(video.id)}
                    >
                      Delete
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>
      ) : activeTab === 'users' ? (
        <section className="user-grid">
          {loading ? (
            <div className="loading">Loading users...</div>
          ) : error ? (
            <div className="error-message">{error}</div>
          ) : users.length === 0 ? (
            <div className="no-users">
              <h3>No users found</h3>
            </div>
          ) : (
            <div className="users-container admin-list">
              {users.map((u) => (
                <div key={u.id} className="user-card admin-card">
                  <div className="user-info">
                    <h3>{u.name}</h3>
                    <p>{u.email}</p>
                    <div className="user-meta">
                      <span>Approved: {u.is_approved ? 'Yes' : 'No'}</span>
                      <span>Admin: {u.is_admin ? 'Yes' : 'No'}</span>
                    </div>
                  </div>
                  <div className="admin-actions">
                    <button 
                      className="btn btn-primary" 
                      onClick={() => approveUser(u.id)}
                      disabled={u.is_approved}
                    >
                      Approve
                    </button>
                    <button 
                      className="btn btn-secondary" 
                      onClick={() => makeAdmin(u.id)}
                      disabled={u.is_admin}
                    >
                      Make Admin
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>
      ) : (
        <section className="upload-section">
          <div className="upload-intro">
            <h3>Upload New Video</h3>
            <p>Upload content directly from the admin panel. After a successful upload, you'll be returned to the Videos tab.</p>
            <button 
              className="btn btn-primary" 
              onClick={() => setShowUploadModal(true)}
              disabled={!user?.is_admin}
              title={!user?.is_admin ? 'Only admins can upload' : ''}
            >
              Open Upload Form
            </button>
            {!user?.is_admin && (
            <p style={{ marginTop: '8px', color: '#ef4444' }}>
              Only admins can upload.
            </p>
            )}
          </div>
        </section>
      )}
 
      {showUploadModal && (
        <UploadForm 
          onClose={() => setShowUploadModal(false)} 
          onSuccess={handleUploadSuccess}
          onNotify={(msg, type) => showToast(msg, type)}
        />
      )}

      {toast.message && (
        <div
          className={`toast ${toast.type}`}
          style={{
            position: 'fixed',
            bottom: '24px',
            right: '24px',
            background: toast.type === 'success' ? '#10b981' : toast.type === 'error' ? '#ef4444' : '#374151',
            color: '#fff',
            padding: '12px 16px',
            borderRadius: '8px',
            boxShadow: '0 10px 15px -3px rgba(0,0,0,0.1), 0 4px 6px -4px rgba(0,0,0,0.1)',
            zIndex: 1000,
            maxWidth: '320px'
          }}
          role="status"
          aria-live="polite"
        >
          {toast.message}
        </div>
      )}
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
  // Removed standalone upload modal state to unify under AdminPanel only
  // const [showUpload, setShowUpload] = useState(false);
  const [loading, setLoading] = useState(true);
  const [showAdmin, setShowAdmin] = useState(false);

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

  if (showAdmin) {
    return <AdminPanel onClose={() => setShowAdmin(false)} />;
  }

  return (
    <div className="app">
      {/* Header */}
      <header className="header">
        <div className="header-content">
          <h1 className="logo">AdultFlix</h1>
          <div className="header-actions">
            {user.is_admin && (
              <button onClick={() => setShowAdmin(true)} className="btn btn-secondary">
                Admin Panel
              </button>
            )}
            {/* Removed standalone Upload button; uploads are available inside Admin Panel */}
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

      {/* Removed standalone Upload modal; UploadForm is accessible via AdminPanel */}
      {/* {showUpload && (
        <UploadForm
          onClose={() => setShowUpload(false)}
          onSuccess={handleUploadSuccess}
        />
      )} */}
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
        const response = await axios.post(`${API}/auth/emergent-login?session_id=${encodeURIComponent(sessionId)}`);

        login(response.data.access_token, response.data.user);
        // Redirect to home after successful login
        window.location.replace('/');
        return;
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