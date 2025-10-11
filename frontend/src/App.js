import React, { useState, useEffect, createContext, useContext, useRef } from 'react';
import './App.css';
import axios from 'axios';

// Prefer explicit backend URL if provided (allows www to use apex API); fallback to same-origin
const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = BACKEND_URL ? `${BACKEND_URL}/api` : '/api';

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
    <AuthContext.Provider value={{ user, login, logout, loading, token }}>
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

// Compress thumbnails client-side for faster loads
async function compressImage(file, maxWidth = 640, quality = 0.7, mimeType = 'image/webp') {
  try {
    if (!file || !(file instanceof File) || !/^image\//.test(file.type)) return file;
    return await new Promise((resolve) => {
      const url = URL.createObjectURL(file);
      const img = new Image();
      img.onload = () => {
        const ratio = img.width ? Math.min(1, maxWidth / img.width) : 1;
        const w = Math.max(1, Math.round(img.width * ratio));
        const h = Math.max(1, Math.round(img.height * ratio));
        const canvas = document.createElement('canvas');
        canvas.width = w; canvas.height = h;
        const ctx = canvas.getContext('2d');
        ctx.drawImage(img, 0, 0, w, h);
        canvas.toBlob((blob) => {
          URL.revokeObjectURL(url);
          if (!blob) return resolve(file);
          const outType = blob.type || mimeType;
          const ext = outType.includes('webp') ? '.webp' : (outType.includes('jpeg') ? '.jpg' : (outType.includes('png') ? '.png' : '.jpg'));
          const name = file.name.replace(/\.[^.]+$/, ext);
          resolve(new File([blob], name, { type: outType }));
        }, mimeType, quality);
      };
      img.onerror = () => { URL.revokeObjectURL(url); resolve(file); };
      img.src = url;
    });
  } catch {
    return file;
  }
}

// Site Footer
const SiteFooter = () => (
  <footer className="site-footer">
    <div className="site-footer-content">
      <div>
        By using this site, you confirm that you are 18 years or older, or the legal age to view adult content in your country.
      </div>
      <div style={{ marginTop: 6 }}>
        <strong>Copyright Notice</strong> — We do not claim ownership to any content on this site. All videos and images are publicly available or shared by others.
      </div>
      <div style={{ marginTop: 6 }}>
        <a href="/privacy" style={{ textDecoration: 'underline' }}>Privacy Policy</a>
        <span> • </span>
        <a href="/dmca" style={{ textDecoration: 'underline' }}>DMCA</a>
      </div>
    </div>
  </footer>
);

// Error Boundary to catch runtime errors in subtrees like the Upload modal
class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }
  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }
  componentDidCatch(error, errorInfo) {
    // Log to console for developer visibility
    console.error('ErrorBoundary caught error:', error, errorInfo);
  }
  handleReset = () => {
    this.setState({ hasError: false, error: null });
  };
  render() {
    if (this.state.hasError) {
      const msg = (this.state.error && (this.state.error.message || String(this.state.error))) || 'Unexpected error';
      return (
        <div className="modal-overlay">
          <div className="modal-content upload-modal">
            <h2>Something went wrong</h2>
            <div className="error-message" style={{ whiteSpace: 'pre-wrap', marginTop: 8 }}>{msg}</div>
            <div className="modal-actions" style={{ marginTop: 12 }}>
              <button className="btn btn-primary" onClick={this.handleReset}>Try again</button>
              {this.props.onClose && (
                <button className="btn btn-secondary" onClick={this.props.onClose} style={{ marginLeft: 8 }}>Close</button>
              )}
            </div>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

// Privacy Policy Page
const PrivacyPolicy = () => {
  return (
    <div className="app page-transition">
      <header className="header">
        <div className="header-content">
          <h1 className="logo" onClick={() => (window.location.href = '/')} style={{ cursor: 'pointer' }}>Bluefilmx</h1>
        </div>
      </header>
      <section className="content" style={{ maxWidth: 900, margin: '24px auto', padding: '0 16px', lineHeight: 1.6 }}>
        <h2>Privacy Policy</h2>
        <p>By using or visiting our site, you agree to the terms and conditions contained herein and all future modifications.</p>
        <p>Our website allows viewing various adult videos, and images and may also contain links to third-party websites which are in no way owned or controlled by us. You acknowledge that we will not be liable for any liability arising from your use of any third-party website.</p>
        <p>You confirm that you are at least eighteen (18) years of age and/or over the age of majority in the jurisdiction you reside and from which you access the website if the age of majority is greater than eighteen (18) years of age. If you are under the age of 18 and/or under the age of majority in the jurisdiction you reside and from which you access the website, then you are not permitted to use the website.</p>
        <p>In sending images or video to our site, you agree that you will not submit content that is copyrighted or subject to third party proprietary rights, nor submit material that is obscene, illegal, unlawful or encourages conduct that would be considered a criminal offense.</p>

        <h3>Comments</h3>
        <p>When visitors leave comments on the site we collect the data shown in the comments form, and also the visitor’s IP address and browser user agent string to help spam detection.</p>
        <p>An anonymized string created from your email address (also called a hash) may be provided to the Gravatar service to see if you are using it. The Gravatar service privacy policy is available here: <a href="https://automattic.com/privacy/" target="_blank" rel="noopener noreferrer">https://automattic.com/privacy/</a>. After approval of your comment, your profile picture is visible to the public in the context of your comment.</p>

        <h3>Media</h3>
        <p>If you upload images to the website, you should avoid uploading images with embedded location data (EXIF GPS) included. Visitors to the website can download and extract any location data from images on the website.</p>

        <h3>Cookies</h3>
        <p>If you leave a comment on our site you may opt-in to saving your name, email address and website in cookies. These are for your convenience so that you do not have to fill in your details again when you leave another comment. These cookies will last for one year.</p>
        <p>If you visit our login page, we will set a temporary cookie to determine if your browser accepts cookies. This cookie contains no personal data and is discarded when you close your browser.</p>
        <p>When you log in, we will also set up several cookies to save your login information and your screen display choices. Login cookies last for two days, and screen options cookies last for a year. If you select “Remember Me”, your login will persist for two weeks. If you log out of your account, the login cookies will be removed.</p>
        <p>If you edit or publish an article, an additional cookie will be saved in your browser. This cookie includes no personal data and simply indicates the post ID of the article you just edited. It expires after 1 day.</p>

        <h3>Embedded content from other websites</h3>
        <p>Articles on this site may include embedded content (e.g. videos, images, articles, etc.). Embedded content from other websites behaves in the exact same way as if the visitor has visited the other website.</p>
        <p>These websites may collect data about you, use cookies, embed additional third-party tracking, and monitor your interaction with that embedded content, including tracking your interaction with the embedded content if you have an account and are logged in to that website.</p>

        <h3>Uses &amp; Disclosure</h3>
        <p>We do not use your email address or other personally identifiable information to send commercial or marketing messages without your consent.</p>
        <p>We do not share your personal information (such as name or email address) third-party companies.</p>
      </section>
      <SiteFooter />
    </div>
  );
};

// DMCA Page
const DmcaPolicy = () => {
  return (
    <div className="app page-transition">
      <header className="header">
        <div className="header-content">
          <h1 className="logo" onClick={() => (window.location.href = '/')} style={{ cursor: 'pointer' }}>Bluefilmx</h1>
        </div>
      </header>
      <section className="content" style={{ maxWidth: 900, margin: '24px auto', padding: '0 16px', lineHeight: 1.6 }}>
        <h2>DMCA</h2>
        <p>Bluefilmx is not governed by U.S. or Canadian law, we have adopted and reasonably implemented policies to voluntarily comply with anti-infringement laws such as the Digital Millennium Copyright Act (“DMCA”) or the Copyright Modernization Act (“CMA”). Under such policies, we assert safe harbor from liability related to alleged copyright infringement committed by third parties. Therefore, we will, in appropriate circumstances, block users who we believe, in our sole and absolute discretion, are repeat copyright infringers, under our voluntary compliance of laws like the DMCA or CMA.</p>
        <p>Bluefilmx is not a producer (primary or secondary) of any or all of the content found on the website. With respect to the records as per 18 USC 2257 for the content found on this site, please kindly direct your request to the site for which the content was produced.</p>
        <p>If your copyrighted material has been posted on our site or if links to your copyrighted material are returned through our search engine and you want this material removed, you must provide a written communication that details the information.</p>
        <p>The following elements must be included in your copyright infringement claim:</p>
        <ul>
          <li>Provide evidence of the authorized person to act on behalf of the owner of an exclusive right that is allegedly infringed.</li>
          <li>Provide sufficient contact information so that we may contact you. You must also include a valid email address.</li>
          <li>You must identify in sufficient detail the copyrighted work claimed to have been infringed and including at least one search term under which the material appears in Bluefilmx search results.</li>
          <li>A statement that the complaining party has a good faith belief that use of the material in the manner complained of is not authorized by the copyright owner, its agent, or the law.</li>
          <li>A statement that the information in the notification is accurate, and under penalty of perjury, that the complaining party is authorized to act on behalf of the owner of an exclusive right that is allegedly infringed.</li>
          <li>Must be signed by the authorized person to act on behalf of the owner of an exclusive right that is allegedly being infringed.</li>
        </ul>
        <p>Send the written infringement notice to the following email address to <a href="mailto:bluefilmx@gmail.com">bluefilmx@gmail.com</a></p>
        <p>Please allow 1-3 business days for an email response. Note that emailing your complaint to other parties such as our Internet Service Provider will not expedite your request and may result in a delayed response due the complaint not properly being filed.</p>
      </section>
      <SiteFooter />
    </div>
  );
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
      const data = error.response?.data || {};
      const code = data.code ? ` (${data.code})` : '';
      setError((data.detail || 'Authentication failed') + code);
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
    <>
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
    <SiteFooter />
    </>
  );
};

// Video Player Component
const VideoPlayer = ({ videoId, onClose }) => {
  const [videoUrl, setVideoUrl] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const { token } = useAuth();
  const sentRef = useRef(false);

  useEffect(() => {
    const t = token || localStorage.getItem('token');
    const url = t
      ? `${API}/videos/${videoId}/stream?token=${encodeURIComponent(t)}`
      : `${API}/videos/${videoId}/stream`;
    setVideoUrl(url);
    setLoading(false);
  }, [videoId, token]);

  const recordView = async () => {
    if (sentRef.current) return;
    sentRef.current = true;
    try { await axios.post(`${API}/videos/${videoId}/view`); } catch {}
  };

  return (
    <div className="video-player-modal">
      <div className="video-player-content">
        <button className="close-button" onClick={onClose}>×</button>
        {loading ? (
          <div className="loading">Loading video...</div>
        ) : error ? (
          <div className="error-container">
            <p>Video failed to load. Try opening directly or another browser.</p>
            <a href={videoUrl} target="_blank" rel="noopener noreferrer" className="btn btn-secondary">Open video</a>
          </div>
        ) : (
              <video
                className="video-player"
                controls
                playsInline
                preload="metadata"
                onPlay={recordView}
                onError={() => setError('failed')}
              >
                <source src={videoUrl} />
                Your browser does not support the video tag.
              </video>
        )}
      </div>
    </div>
  );
};

// Dedicated Video Page Component
const VideoPage = ({ videoId, navigate }) => {
  const { user, logout } = useAuth();
  const [videoUrl, setVideoUrl] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [meta, setMeta] = useState(null);
  const [nextList, setNextList] = useState([]);
  const viewSentRef = useRef(false);
  const playerRef = useRef(null);
  const autoplayRef = useRef(false);
  const handleShare = async () => {
    try {
      const url = `${window.location.origin}/video/${videoId}`;
      const title = meta?.title || 'Bluefilmx Video';
      const text = `${title} — Watch on Bluefilmx`;
      if (navigator.share) {
        await navigator.share({ title, text, url });
      } else {
        try { await navigator.clipboard.writeText(url); alert('Link copied'); }
        catch { window.prompt('Copy this link', url); }
      }
    } catch {}
  };
  const handleLogoutClick = () => {
    logout();
    if (navigate) navigate('/'); else window.location.href = '/';
  };

  useEffect(() => {
    // Default to same-origin stream without token for caching and faster TTFB
    setVideoUrl(`${API}/videos/${videoId}/stream`);
    setLoading(false);
    // Detect autoplay flag from query string; reset view tracking on video change
    try {
      const q = new URLSearchParams(window.location.search);
      autoplayRef.current = q.get('autoplay') === '1';
    } catch {}
    viewSentRef.current = false;
    // Pause any playing instance on id switch
    try { if (playerRef.current) { playerRef.current.pause(); } } catch {}
  }, [videoId]);

  // Ensure the <video> element reloads when the URL changes
  useEffect(() => {
    try { if (playerRef.current) { playerRef.current.load(); } } catch {}
  }, [videoUrl]);

  useEffect(() => {
    let cancelled = false;
    const fetchMeta = async () => {
      try {
        const res = await axios.get(`${API}/videos/${videoId}`);
        if (!cancelled) {
          setMeta(res.data);
          if (res.data?.title) document.title = `${res.data.title} • Bluefilmx`;
          // For admins previewing non-approved videos, add token to stream URL
          if (res.data?.status !== 'approved' && user) {
            const t = localStorage.getItem('token');
            if (t) setVideoUrl(`${API}/videos/${videoId}/stream?token=${encodeURIComponent(t)}`);
          }
        }
      } catch {}
    };
    fetchMeta();
    return () => { cancelled = true; };
  }, [videoId, user]);

  useEffect(() => {
    let cancelled = false;
    const fetchNext = async () => {
      if (!meta) return;
      try {
        const res = await axios.get(`${API}/videos`);
        if (!cancelled) {
          const list = Array.isArray(res.data) ? res.data : [];
          const all = list.filter(v => String(v.id) !== String(videoId));
          const byCat = meta?.category ? all.filter(v => v.category === meta.category) : all;
          const byCatIds = new Set(byCat.map(v => String(v.id)));
          const fill = all.filter(v => !byCatIds.has(String(v.id)));
          const finalList = [...byCat, ...fill].slice(0, 4);
          setNextList(finalList);
        }
      } catch {}
    };
    fetchNext();
    return () => { cancelled = true; };
  }, [meta, videoId]);

  // No auto-generated thumbnails; Up Next will use custom thumbnails if present

  return (
    <div className="app page-transition">
      <header className="header">
        <div className="header-content">
          <h1 className="logo" onClick={() => (navigate ? navigate('/') : (window.location.href = '/'))}>Bluefilmx</h1>
          <div className="header-actions">
            <button onClick={() => window.history.back()} className="btn btn-secondary">Back</button>
            {user && (
              <div className="user-menu">
                <span>Welcome, {user.name}</span>
                <button onClick={handleLogoutClick} className="btn btn-secondary">Logout</button>
              </div>
            )}
          </div>
        </div>
      </header>

      <section className="video-page">
        <div className="video-layout">
          <div className="video-main">
            {meta?.title && <h2 className="video-title">{meta.title}</h2>}
            {loading ? (
              <div className="loading">Loading video...</div>
            ) : error ? (
              <div className="error-container">
                <p>Video failed to load. Try opening directly or another browser.</p>
                <a href={videoUrl} target="_blank" rel="noopener noreferrer" className="btn btn-secondary">Open video</a>
              </div>
            ) : (
              <video
                key={String(videoId)}
                ref={playerRef}
                className="video-player"
                controls
                playsInline
                preload="metadata"
                poster={meta?.thumbnail_key ? `${API}/videos/${videoId}/thumbnail` : undefined}
                src={videoUrl}
                onLoadedMetadata={async () => {
                  if (autoplayRef.current && playerRef.current) {
                    try { await playerRef.current.play(); } catch {}
                  }
                }}
                onPlay={async () => {
                  if (viewSentRef.current) return;
                  viewSentRef.current = true;
                  try {
                    const res = await axios.post(`${API}/videos/${videoId}/view`);
                    if (res?.data?.views != null) setMeta((m) => (m ? { ...m, views: res.data.views } : m));
                  } catch {}
                }}
                onError={() => setError('failed')}
              >
                Your browser does not support the video tag.
              </video>
            )}
            {meta && (
              <div className="video-meta-block">
                <div className="video-primary-meta">
                  <span className="category">{meta.category}</span>
                  <span className="views">{meta.views} views</span>
                  <span className="status" style={{ color: '#888', marginLeft: 8 }}>• {meta.status}</span>
                  <button onClick={handleShare} className="btn btn-secondary" style={{ marginLeft: 8 }}>Share</button>
                </div>
                {meta.description && (
                  <p className="video-description">{meta.description}</p>
                )}
                {Array.isArray(meta.tags) && meta.tags.length > 0 && (
                  <div className="video-tags" style={{ marginTop: 8 }}>
                    {meta.tags.map(tag => (
                      <span key={tag} className="tag">{tag}</span>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
          <aside className="video-aside">
            <h3 className="up-next-title">Up next</h3>
            <div className="next-list">
              {nextList.map(v => (
                <a
                  key={v.id}
                  className="next-card"
                  href={`/video/${v.id}?autoplay=1`}
                  onClick={(e) => {
                    if (!navigate) return;
                    if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return; // let new-tab etc. work
                    e.preventDefault();
                    navigate(`/video/${v.id}?autoplay=1`);
                  }}
                >
                  <div className="next-thumb">
                    {v.thumbnail_key ? (
                      <img
                        loading="lazy"
                        decoding="async"
                        width={240}
                        height={135}
                        src={`${API}/videos/${v.id}/thumbnail`}
                        alt={v.title}
                      />
                    ) : null}
                  </div>
                  <div className="next-info">
                    <div className="next-title">{v.title}</div>
                    <div className="next-meta">{v.category} • {v.views} views</div>
                  </div>
                </a>
              ))}
              {nextList.length === 0 && (
                <div className="next-empty">No recommendations</div>
              )}
            </div>
          </aside>
        </div>
      </section>
      <SiteFooter />
    </div>
  );
};

// Video Card Component
const VideoCard = ({ video, navigate, priority = false }) => {
  const href = `/video/${video.id}`;
  const [previewing, setPreviewing] = useState(false);
  const videoRef = useRef(null);
  const previewTimerRef = useRef(null);
  const rootRef = useRef(null);
  const previewSrc = `${API}/videos/${video.id}/stream?preview=1`;
  const canHover = typeof window !== 'undefined' && window.matchMedia && window.matchMedia('(hover: hover) and (pointer: fine)').matches;
  const reduceMotion = typeof window !== 'undefined' && window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const saveData = typeof navigator !== 'undefined' && navigator.connection && navigator.connection.saveData;
  const previewId = `vid-${video.id}`;
  const share = async (e) => {
    if (e && typeof e.preventDefault === 'function') { e.preventDefault(); e.stopPropagation(); }
    try {
      const url = `${window.location.origin}/video/${video.id}`;
      const title = video.title || 'Bluefilmx Video';
      const text = `${title} — Watch on Bluefilmx`;
      if (navigator.share) {
        await navigator.share({ title, text, url });
      } else {
        try { await navigator.clipboard.writeText(url); alert('Link copied'); }
        catch { window.prompt('Copy this link', url); }
      }
    } catch {}
  };

  // simple global bus to ensure only one preview plays at a time
  if (typeof window !== 'undefined' && !window.__previewBus) {
    try { window.__previewBus = new EventTarget(); } catch {}
  }

  const stopPreview = () => {
    if (previewTimerRef.current) clearTimeout(previewTimerRef.current);
    try {
      if (videoRef.current) {
        videoRef.current.pause();
        videoRef.current.currentTime = 0;
      }
    } catch {}
    setPreviewing(false);
  };

  const startPreview = () => {
    if (reduceMotion || saveData) return;
    setPreviewing(true);
    if (previewTimerRef.current) clearTimeout(previewTimerRef.current);
    previewTimerRef.current = setTimeout(() => {
      stopPreview();
    }, 6000);
    try { window.__previewBus && window.__previewBus.dispatchEvent(new CustomEvent('preview-start', { detail: { id: previewId } })); } catch {}
  };

  const handleClick = (e) => {
    if (!navigate) return;
    if (e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    e.preventDefault();
    navigate(href);
  };

  const handleEnter = () => { if (!canHover) return; startPreview(); };

  const handleLeave = () => { if (!canHover) return; stopPreview(); };

  // Stop timers on unmount
  useEffect(() => () => { if (previewTimerRef.current) clearTimeout(previewTimerRef.current); }, []);

  // Ensure only one preview at a time
  useEffect(() => {
    const onStart = (e) => {
      if (!e?.detail || e.detail.id === previewId) return;
      stopPreview();
    };
    try { window.__previewBus && window.__previewBus.addEventListener('preview-start', onStart); } catch {}
    return () => { try { window.__previewBus && window.__previewBus.removeEventListener('preview-start', onStart); } catch {} };
  }, [previewId]);

  // Auto preview on mobile (no hover) using IntersectionObserver
  useEffect(() => {
    if (canHover || reduceMotion || saveData) return; // desktop handles via hover; respect user settings
    const el = rootRef.current;
    if (!el || !('IntersectionObserver' in window)) return;
    const io = new IntersectionObserver((entries) => {
      for (const entry of entries) {
        if (entry.isIntersecting && entry.intersectionRatio >= 0.6) {
          startPreview();
        } else {
          stopPreview();
        }
      }
    }, { threshold: [0, 0.6, 1] });
    io.observe(el);
    return () => { try { io.disconnect(); } catch {} };
  }, [canHover, reduceMotion, saveData]);

  return (
    <a className="video-card" href={href} onClick={handleClick}>
      <div ref={rootRef} className={`video-thumbnail ${previewing ? 'previewing' : ''}`} onMouseEnter={handleEnter} onMouseLeave={handleLeave}>
        <button
          type="button"
          className="btn btn-secondary"
          onClick={share}
          style={{ position: 'absolute', top: 8, right: 8, zIndex: 3, padding: '4px 8px', fontSize: 12 }}
          aria-label="Share video"
        >
          Share
        </button>
        {previewing ? (
          <video
            ref={videoRef}
            className="thumb-video"
            src={previewSrc}
            muted
            playsInline
            autoPlay
            preload="metadata"
            poster={video.thumbnail_key ? `${API}/videos/${video.id}/thumbnail` : undefined}
          />
        ) : video.thumbnail_key ? (
          <img
            loading="lazy"
            decoding="async"
            fetchPriority={priority ? 'high' : 'auto'}
            width={400}
            height={225}
            src={`${API}/videos/${video.id}/thumbnail`}
            alt={video.title}
          />
        ) : (
          <div className="thumb-skel" />
        )}
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
          {(Array.isArray(video.tags)
            ? video.tags
            : (typeof video.tags === 'string' ? video.tags.split(',').map((t) => t.trim()).filter(Boolean) : [])
            ).map(tag => (
            <span key={tag} className="tag">{tag}</span>
          ))}
        </div>
      </div>
    </a>
  );
};

// Add configurable max upload size (in MB) with a safe default
const MAX_UPLOAD_MB = Number(process.env.REACT_APP_MAX_UPLOAD_MB || 200);
const MAX_UPLOAD_BYTES = MAX_UPLOAD_MB * 1024 * 1024;

// Upload Form Component
const UploadForm = ({ onClose, onSuccess, onNotify }) => {
   const [formData, setFormData] = useState({
     title: '',
     description: '',
     category: '',
     tags: ''
   });
   const [file, setFile] = useState(null);
   const [thumbFile, setThumbFile] = useState(null);
   const [uploading, setUploading] = useState(false);
   const [uploadProgress, setUploadProgress] = useState(0);
   const [error, setError] = useState('');
 
   const handleFileChange = (e) => {
     const f = e.target.files && e.target.files[0];
     if (!f) return;
     if (f.size > MAX_UPLOAD_BYTES) {
       const msg = `File is too large. Max allowed is ${MAX_UPLOAD_MB} MB. Selected is ${Math.ceil(f.size / 1024 / 1024)} MB.`;
       setError(msg);
       onNotify && onNotify(msg, 'error');
       e.target.value = '';
       setFile(null);
       return;
     }
     setFile(f);
     setError('');
   };

   // Thumbnail change handled inline in JSX to avoid symbol resolution issues
 
  const handleSubmit = async (e) => {
     e.preventDefault();
     if (!file) {
       setError('Please select a video file');
       onNotify && onNotify('Please select a video file', 'error');
       return;
     }
     if (file.size > MAX_UPLOAD_BYTES) {
       const msg = `File is too large. Max allowed is ${MAX_UPLOAD_MB} MB. Selected is ${Math.ceil(file.size / 1024 / 1024)} MB.`;
       setError(msg);
       onNotify && onNotify(msg, 'error');
       return;
     }

     setUploading(true);
     setUploadProgress(0);
     setError('');

    try {
      const contentType = file.type || 'application/octet-stream';
      console.log('Using direct-to-R2 upload via presigned URL');

      // 1) Request an upload URL from backend; prefer same-origin binding to avoid CORS
      const presignRes = await axios.post(`${API}/uploads/presign`, {
        filename: file.name,
        contentType,
        preferBinding: true
      });
      const { uploadUrl, storageKey } = presignRes.data || {};
      if (!uploadUrl || !storageKey) {
        throw new Error('Failed to obtain upload URL');
      }

      // 2) Upload file
      setUploadProgress(5);
      const isBindingPutVideo = /\/api\/uploads\/put/.test(uploadUrl);
      if (isBindingPutVideo) {
        const token = localStorage.getItem('token') || '';
        const res = await fetch(uploadUrl, {
          method: 'PUT',
          headers: {
            'Content-Type': contentType,
            ...(token ? { Authorization: `Bearer ${token}` } : {}),
          },
          body: file,
        });
        if (!res.ok) throw new Error(`Video PUT failed: ${res.status}`);
      } else {
        // Direct-to-R2 via presigned URL (CORS required)
        await new Promise((resolve, reject) => {
          const xhr = new XMLHttpRequest();
          xhr.open('PUT', uploadUrl, true);
          try { xhr.setRequestHeader('Content-Type', contentType); } catch {}
          try {
            const u = new URL(uploadUrl);
            const signedHeaders = (u.searchParams.get('X-Amz-SignedHeaders') || u.searchParams.get('x-amz-signedheaders') || '').toLowerCase();
            const checksumAlg = u.searchParams.get('x-amz-checksum-algorithm');
            xhr.setRequestHeader('x-amz-content-sha256', 'UNSIGNED-PAYLOAD');
            if (checksumAlg && signedHeaders.includes('x-amz-checksum-algorithm')) {
              xhr.setRequestHeader('x-amz-checksum-algorithm', checksumAlg);
            }
          } catch {}
          xhr.upload.onprogress = (e) => {
            if (e.lengthComputable && e.total) {
              const progress = Math.round((e.loaded * 100) / e.total);
              setUploadProgress(progress);
            }
          };
          xhr.onload = () => {
            if (xhr.status >= 200 && xhr.status < 300) resolve(null);
            else reject(new Error(`R2 PUT failed: ${xhr.status} ${xhr.statusText}`));
          };
          xhr.onerror = () => reject(new Error('R2 PUT network error'));
          xhr.send(file);
        });
      }

      // 3) Optionally upload thumbnail (compress client-side for faster loads)
      let thumbnailKey;
      if (thumbFile) {
        const compressed = await compressImage(thumbFile, 640, 0.7, 'image/webp');
        const upThumb = compressed || thumbFile;
        const thumbContentType = upThumb.type || 'image/jpeg';
        const presignThumb = await axios.post(`${API}/uploads/presign`, {
          filename: upThumb.name,
          contentType: thumbContentType,
          preferBinding: true
        });
        const { uploadUrl: tUrl, storageKey: tKey } = presignThumb.data || {};
        if (!tUrl || !tKey) throw new Error('Failed to obtain thumbnail upload URL');
        const isBindingPut = /\/api\/uploads\/put/.test(tUrl);
        if (isBindingPut) {
          const token = localStorage.getItem('token') || '';
          const res = await fetch(tUrl, {
            method: 'PUT',
            headers: {
              'Content-Type': thumbContentType,
              ...(token ? { Authorization: `Bearer ${token}` } : {}),
            },
            body: upThumb,
          });
          if (!res.ok) throw new Error(`Thumbnail PUT failed: ${res.status}`);
        } else {
          await new Promise((resolve, reject) => {
            const xhr2 = new XMLHttpRequest();
            xhr2.open('PUT', tUrl, true);
            try { xhr2.setRequestHeader('Content-Type', thumbContentType); } catch {}
            try {
              const u2 = new URL(tUrl);
              const signedHeaders2 = (u2.searchParams.get('X-Amz-SignedHeaders') || u2.searchParams.get('x-amz-signedheaders') || '').toLowerCase();
              const checksumAlg2 = u2.searchParams.get('x-amz-checksum-algorithm');
              xhr2.setRequestHeader('x-amz-content-sha256', 'UNSIGNED-PAYLOAD');
              if (checksumAlg2 && signedHeaders2.includes('x-amz-checksum-algorithm')) {
                xhr2.setRequestHeader('x-amz-checksum-algorithm', checksumAlg2);
              }
            } catch {}
            xhr2.onload = () => {
              if (xhr2.status >= 200 && xhr2.status < 300) resolve(null);
              else reject(new Error(`Thumbnail PUT failed: ${xhr2.status} ${xhr2.statusText}`));
            };
            xhr2.onerror = () => reject(new Error('Thumbnail PUT network error'));
            xhr2.send(upThumb);
          });
        }
        thumbnailKey = tKey;
      }

      // 4) Create the video record in our database (with optional thumbnail)
      const createRes = await axios.post(`${API}/videos`, {
        title: formData.title,
        description: formData.description,
        category: formData.category,
        tags: formData.tags,
        storageKey,
        thumbnailKey
      });
      console.log('Create video response:', createRes.data);

      setUploadProgress(100);
      onNotify && onNotify('Upload successful', 'success');
      onSuccess();

    } catch (error) {
      console.error('Direct upload error:', error);
      const NETLIFY_FALLBACK_MAX_BYTES = 10 * 1024 * 1024; // Netlify function payload limit ~10MB
      const shouldFallback =
        file.size <= NETLIFY_FALLBACK_MAX_BYTES &&
        (!error?.response || error?.code === 'ERR_NETWORK');

      let message;

      if (shouldFallback) {
        try {
          console.log('Falling back to server-side upload');
          setError('');

          const fd = new FormData();
          fd.append('file', file);
          fd.append('title', formData.title);
          fd.append('description', formData.description);
          fd.append('category', formData.category);
          fd.append('tags', formData.tags);

          setUploadProgress(5);
          const uploadRes = await axios.post(`${API}/videos/upload`, fd, {
            headers: { 'Content-Type': 'multipart/form-data' },
            onUploadProgress: (progressEvent) => {
              if (progressEvent.total) {
                const progress = Math.round((progressEvent.loaded * 100) / progressEvent.total);
                setUploadProgress(progress);
              }
            },
            timeout: 300000
          });

          console.log('Server-side fallback upload response:', uploadRes.data);
          setUploadProgress(100);
          onNotify && onNotify('Upload successful via fallback path', 'success');
          onSuccess();
          return;
        } catch (fallbackErr) {
          console.error('Server-side fallback upload error:', fallbackErr);
          message = fallbackErr?.response?.data?.detail
            || fallbackErr?.message
            || 'Upload failed';
        }
      } else {
        message = error?.response?.data?.detail
          || error?.message
          || (file.size > NETLIFY_FALLBACK_MAX_BYTES
            ? 'Upload failed. Files over 10MB must use the direct-to-R2 path. Ensure R2 CORS allows https://bluefilmx.com.'
            : 'Upload failed. If this persists, ensure R2 CORS allows https://bluefilmx.com.');
      }

      setError(message);
      onNotify && onNotify(message, 'error');
    } finally {
      setUploading(false);
    }

    return;
  }

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
            onChange={handleFileChange}
            required
          />
          <div style={{ fontSize: '12px', color: '#aaa', marginTop: '4px' }}>Max size: {MAX_UPLOAD_MB} MB</div>
          <div style={{ height: 8 }} />
          <input
            type="file"
            accept="image/*"
            onChange={(e) => {
              const f = e.target.files && e.target.files[0];
              if (!f) { setThumbFile(null); return; }
              if (!/^image\//.test(f.type || '')) {
                const msg = 'Thumbnail must be an image file';
                setError(msg);
                onNotify && onNotify(msg, 'error');
                e.target.value = '';
                setThumbFile(null);
                return;
              }
              if (f.size > 5 * 1024 * 1024) {
                const msg = 'Thumbnail is too large. Max 5MB.';
                setError(msg);
                onNotify && onNotify(msg, 'error');
                e.target.value = '';
                setThumbFile(null);
                return;
              }
              setThumbFile(f);
              setError('');
            }}
          />
          <div style={{ fontSize: '12px', color: '#aaa', marginTop: '4px' }}>Optional thumbnail image (max 5MB)</div>

          {uploading && (
            <div style={{ marginTop: 12 }}>
              <div style={{ height: 8, background: '#333', borderRadius: 4, overflow: 'hidden' }}>
                <div style={{ height: '100%', width: `${uploadProgress}%`, background: '#e50914', transition: 'width 0.2s ease' }} />
              </div>
              <div style={{ marginTop: 6, fontSize: 12, color: '#aaa' }}>{uploadProgress}%</div>
            </div>
          )}
          
          <div className="modal-actions">
            <button type="submit" disabled={uploading} className="btn btn-primary">
              {uploading ? 'Uploading...' : 'Upload Video'}
            </button>
            <button type="button" onClick={onClose} className="btn btn-secondary" disabled={uploading}>
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
  const [editingId, setEditingId] = useState(null);
  const [editTitle, setEditTitle] = useState('');
  const [editDesc, setEditDesc] = useState('');
  // Toast state for inline notifications within AdminPanel
  const [toast, setToast] = useState({ message: '', type: '' });
  // Thumbnail edit helpers
  const thumbInputRef = useRef(null);
  const [thumbTargetVideoId, setThumbTargetVideoId] = useState(null);
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

  const startEdit = (v) => {
    setEditingId(v.id);
    setEditTitle(v.title || '');
    setEditDesc(v.description || '');
  };
  const cancelEdit = () => {
    setEditingId(null);
    setEditTitle('');
    setEditDesc('');
  };
  const saveEdit = async (id) => {
    try {
      await axios.put(`${API}/videos/${id}`, { title: editTitle, description: editDesc });
      showToast('Video updated', 'success');
      cancelEdit();
      await loadVideos();
    } catch (err) {
      showToast(err.response?.data?.detail || 'Failed to update video', 'error');
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

  const editThumbnailClick = (videoId) => {
    setThumbTargetVideoId(videoId);
    if (thumbInputRef.current) {
      thumbInputRef.current.value = '';
      thumbInputRef.current.click();
    }
  };

  const onThumbFileChange = async (e) => {
    const f = e.target.files && e.target.files[0];
    if (!f || !thumbTargetVideoId) return;
    if (!/^image\//.test(f.type || '')) {
      showToast('Thumbnail must be an image', 'error');
      return;
    }
    if (f.size > 5 * 1024 * 1024) {
      showToast('Thumbnail too large (max 5MB)', 'error');
      return;
    }
    try {
      // Compress client-side for faster loads
      const cf = await compressImage(f, 640, 0.7, 'image/webp');
      const up = cf || f;
      // Presign and upload thumbnail to R2
      const presign = await axios.post(`${API}/uploads/presign`, {
        filename: up.name,
        contentType: up.type || 'image/jpeg',
        preferBinding: true
      });
      const { uploadUrl, storageKey } = presign.data || {};
      if (!uploadUrl || !storageKey) throw new Error('Failed to get thumbnail upload URL');
      if (/\/api\/uploads\/put/.test(uploadUrl)) {
      const token = localStorage.getItem('token') || '';
      const res = await fetch(uploadUrl, {
        method: 'PUT',
        headers: {
          'Content-Type': up.type || 'image/jpeg',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: up,
      });
      if (!res.ok) throw new Error(`Thumbnail PUT failed: ${res.status}`);
    } else {
      await new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest();
        xhr.open('PUT', uploadUrl, true);
        try { xhr.setRequestHeader('Content-Type', up.type || 'image/jpeg'); } catch {}
        try {
          const u = new URL(uploadUrl);
          const signedHeaders = (u.searchParams.get('X-Amz-SignedHeaders') || u.searchParams.get('x-amz-signedheaders') || '').toLowerCase();
          const checksumAlg = u.searchParams.get('x-amz-checksum-algorithm');
          xhr.setRequestHeader('x-amz-content-sha256', 'UNSIGNED-PAYLOAD');
          if (checksumAlg && signedHeaders.includes('x-amz-checksum-algorithm')) {
            xhr.setRequestHeader('x-amz-checksum-algorithm', checksumAlg);
          }
        } catch {}
        xhr.onload = () => {
          if (xhr.status >= 200 && xhr.status < 300) resolve(null);
          else reject(new Error(`Thumbnail PUT failed: ${xhr.status} ${xhr.statusText}`));
        };
        xhr.onerror = () => reject(new Error('Thumbnail PUT network error'));
        xhr.send(up);
      });
    }
      // Update video record to point to new thumbnail
      await axios.put(`${API}/videos/${thumbTargetVideoId}/thumbnail`, { thumbnailKey: storageKey });
      showToast('Thumbnail updated', 'success');
      await loadVideos();
    } catch (err) {
      showToast(err.response?.data?.detail || err.message || 'Failed to update thumbnail', 'error');
    } finally {
      setThumbTargetVideoId(null);
      if (thumbInputRef.current) thumbInputRef.current.value = '';
    }
  };

  const removeThumbnail = async (videoId) => {
    try {
      await axios.put(`${API}/videos/${videoId}/thumbnail`, { thumbnailKey: '' });
      showToast('Thumbnail removed', 'success');
      await loadVideos();
    } catch (err) {
      showToast(err.response?.data?.detail || 'Failed to remove thumbnail', 'error');
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
                <div key={video.id} className="video-card admin-card" style={{ display: 'grid', gridTemplateColumns: '200px 1fr', gap: 12 }}>
                  <div className="video-thumb-admin" style={{ width: '100%', height: 112, background: '#1f2937', borderRadius: 8, overflow: 'hidden', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                    {video.thumbnail_key ? (
                      <img loading="lazy" src={`${API}/videos/${video.id}/thumbnail`} alt={video.title} style={{ width: '100%', height: '100%', objectFit: 'cover', display: 'block' }} />
                    ) : (
                      <span style={{ color: '#9ca3af', fontSize: 12 }}>No thumbnail</span>
                    )}
                  </div>
                  <div>
                    <div className="video-info" style={{ padding: 0 }}>
                      {editingId === video.id ? (
                        <>
                          <input
                            type="text"
                            value={editTitle}
                            onChange={(e) => setEditTitle(e.target.value)}
                            placeholder="Title"
                            style={{ width: '100%', marginBottom: 6 }}
                          />
                          <textarea
                            value={editDesc}
                            onChange={(e) => setEditDesc(e.target.value)}
                            placeholder="Description"
                            rows={3}
                            style={{ width: '100%' }}
                          />
                        </>
                      ) : (
                        <>
                          <h3>{video.title}</h3>
                          <p>{video.description}</p>
                        </>
                      )}
                      <div className="video-meta">
                        <span className="category">{video.category}</span>
                        <span className="views">{video.views} views</span>
                        <span className="status">Status: {video.status}</span>
                        <span style={{ marginLeft: 8, color: video.thumbnail_key ? '#10b981' : '#ef4444' }}>• {video.thumbnail_key ? 'Has thumb' : 'No thumb'}</span>
                      </div>
                      <div className="video-tags">
                        {(video.tags || []).map(tag => (
                          <span key={tag} className="tag">{tag}</span>
                        ))}
                      </div>
                    </div>
                    <div className="admin-actions" style={{ marginTop: 8 }}>
                      {editingId === video.id ? (
                        <>
                          <button
                            className="btn btn-primary"
                            onClick={() => saveEdit(video.id)}
                            disabled={!editTitle.trim() || !editDesc.trim()}
                          >
                            Save
                          </button>
                          <button className="btn btn-secondary" onClick={cancelEdit} style={{ marginLeft: 8 }}>Cancel</button>
                        </>
                      ) : (
                        <button className="btn btn-secondary" onClick={() => startEdit(video)}>
                          Edit Details
                        </button>
                      )}
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
                        className="btn btn-secondary"
                        onClick={() => editThumbnailClick(video.id)}
                        title="Add/Replace Thumbnail"
                      >
                        Edit Thumbnail
                      </button>
                      {video.thumbnail_key && (
                        <button
                          className="btn btn-secondary"
                          onClick={() => removeThumbnail(video.id)}
                          title="Remove Thumbnail"
                        >
                          Remove Thumbnail
                        </button>
                      )}
                      <button 
                        className="btn btn-danger" 
                        onClick={() => deleteVideo(video.id)}
                      >
                        Delete
                      </button>
                    </div>
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
        <ErrorBoundary onClose={() => setShowUploadModal(false)}>
          <UploadForm 
            onClose={() => setShowUploadModal(false)} 
            onSuccess={handleUploadSuccess}
            onNotify={(msg, type) => showToast(msg, type)}
          />
        </ErrorBoundary>
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
      <SiteFooter />
      {/* Hidden input for editing thumbnails */}
      <input
        ref={thumbInputRef}
        type="file"
        accept="image/*"
        style={{ display: 'none' }}
        onChange={onThumbFileChange}
      />
    </div>
  );
};

// Main App Component
const MainApp = ({ navigate }) => {
  const { user, logout } = useAuth();
  const [videos, setVideos] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(24);
  const [isSearching, setIsSearching] = useState(false);
  const [categories, setCategories] = useState([]);
  const [selectedCategory, setSelectedCategory] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [currentVideo, setCurrentVideo] = useState(null);
  // Removed standalone upload modal state to unify under AdminPanel only
  // const [showUpload, setShowUpload] = useState(false);
  const [loading, setLoading] = useState(true);
  const [showAdmin, setShowAdmin] = useState(false);

  useEffect(() => {
    // reset pagination when filter changes
    setVideos([]);
    setPage(0);
    setIsSearching(false);
    fetchVideos(0, true);
    fetchCategories();
  }, [selectedCategory]);

  const fetchVideos = async (pageToLoad = page, reset = false) => {
    try {
      const params = {
        ...(selectedCategory ? { category: selectedCategory } : {}),
        limit: pageSize,
        offset: pageToLoad * pageSize,
      };
      const response = await axios.get(`${API}/videos`, { params });
      const totalCount = Number(response.headers['x-total-count'] || 0);
      const data = Array.isArray(response.data) ? response.data : [];
      setTotal(totalCount || (reset ? data.length : total));
      setVideos((prev) => (reset ? data : [...prev, ...data]));
    } catch (error) {
      console.error('Failed to fetch videos:', error);
    } finally {
      setLoading(false);
    }
  };

  const fetchCategories = async () => {
    try {
      const response = await axios.get(`${API}/categories`);
      const cats = Array.isArray(response.data?.categories) ? response.data.categories : [];
      setCategories(cats);
    } catch (error) {
      console.error('Failed to fetch categories:', error);
    }
  };

  const handleSearch = async () => {
    if (!searchQuery.trim()) {
      setIsSearching(false);
      setVideos([]);
      setPage(0);
      fetchVideos(0, true);
      return;
    }

    try {
      setIsSearching(true);
      const response = await axios.post(`${API}/search?limit=${pageSize}&offset=0`, {
        query: searchQuery,
        category: selectedCategory || null
      });
      const totalCount = Number(response.headers['x-total-count'] || 0);
      const data = Array.isArray(response.data) ? response.data : [];
      setTotal(totalCount || data.length);
      setPage(0);
      setVideos(data);
    } catch (error) {
      console.error('Search failed:', error);
    }
  };

  const handleUploadSuccess = () => {
    fetchVideos();
  };

  const handleLogoClick = async () => {
    setSelectedCategory('');
    setSearchQuery('');
    setIsSearching(false);
    setPage(0);
    setVideos([]);
    try {
      await fetchVideos(0, true);
    } catch (e) {
      console.error('Failed to reload videos:', e);
    }
    if (navigate && window.location.pathname !== '/') {
      navigate('/');
    } else {
      try { window.scrollTo({ top: 0, behavior: 'smooth' }); } catch { window.scrollTo(0, 0); }
    }
  };

  const handleLogout = async () => {
    logout();
    setShowAdmin(false);
    setSelectedCategory('');
    setSearchQuery('');
    setIsSearching(false);
    setVideos([]);
    setPage(0);
    try {
      await fetchVideos(0, true);
    } catch {}
    if (navigate && window.location.pathname !== '/') {
      navigate('/');
    } else {
      try { window.scrollTo({ top: 0, behavior: 'smooth' }); } catch { window.scrollTo(0, 0); }
    }
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
          <h1
            className="logo"
            onClick={handleLogoClick}
            style={{ cursor: 'pointer' }}
          >
            Bluefilmx
          </h1>
          <div className="header-actions">
            {user?.is_admin && (
              <button onClick={() => setShowAdmin(true)} className="btn btn-secondary">
                Admin Panel
              </button>
            )}
            {/* Removed standalone Upload button; uploads are available inside Admin Panel */}
            {user ? (
              <div className="user-menu">
                <span>Welcome, {user.name}</span>
                <button onClick={handleLogout} className="btn btn-secondary">Logout</button>
              </div>
            ) : (
              <div className="user-menu">
                <button onClick={() => (window.location.href = '/login')} className="btn btn-primary">Sign In</button>
              </div>
            )}
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
          <img loading="lazy" src="https://images.unsplash.com/photo-1717295248358-4b8f2c8989d6?w=1200&h=400&fit=crop" alt="Premium streaming" />
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
              {(Array.isArray(categories) ? categories : []).map(category => (
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
            {videos.map((video, idx) => (
              <VideoCard
                key={video.id}
                video={video}
                navigate={navigate}
                priority={idx < 6}
              />
            ))}
            {(videos.length < total) && (
              <div style={{ width: '100%', display: 'flex', justifyContent: 'center', marginTop: 16 }}>
                <button
                  className="btn btn-secondary"
                  onClick={async () => {
                    const next = page + 1;
                    setPage(next);
                    if (isSearching) {
                      try {
                        const res = await axios.post(`${API}/search?limit=${pageSize}&offset=${next * pageSize}`,
                          { query: searchQuery, category: selectedCategory || null });
                        const more = Array.isArray(res.data) ? res.data : [];
                        setVideos((prev) => [...prev, ...more]);
                      } catch {}
                    } else {
                      await fetchVideos(next);
                    }
                  }}
                >
                  Load more
                </button>
              </div>
            )}
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
      <SiteFooter />
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
    <ErrorBoundary>
      <AuthProvider>
        <AppRouter />
      </AuthProvider>
    </ErrorBoundary>
  );
};

const AppRouter = () => {
  const { user, loading, logout } = useAuth();
  const [showApprovalMessage, setShowApprovalMessage] = useState(false);
  const [path, setPath] = useState(window.location.pathname);

  useEffect(() => {
    if (user && !user.is_approved) {
      setShowApprovalMessage(true);
    }
  }, [user]);

  useEffect(() => {
    const onPop = () => setPath(window.location.pathname);
    window.addEventListener('popstate', onPop);
    return () => window.removeEventListener('popstate', onPop);
  }, []);

  const navigate = (to) => {
    const url = new URL(to, window.location.origin);
    const nextPath = url.pathname;
    if (nextPath !== window.location.pathname || url.search !== window.location.search) {
      window.history.pushState({}, '', to);
      setPath(nextPath);
      try { window.scrollTo({ top: 0, behavior: 'smooth' }); } catch { window.scrollTo(0, 0); }
    }
  };

  if (loading) {
    return <div className="loading">Loading...</div>;
  }

  // Handle auth callback
  if (path === '/auth/callback') {
    return <AuthCallback />;
  }

  // Privacy Policy route
  if (path === '/privacy') {
    return <PrivacyPolicy />;
  }

  // DMCA route
  if (path === '/dmca') {
    return <DmcaPolicy />;
  }

  // Public default: show homepage; only show auth forms on explicit routes
  if (!user) {
    if (path === '/login' || path === '/register' || path === '/auth') {
      return <AuthForms />;
    }
    // fall through to MainApp for anonymous homepage
  }

  // Do not hard-block browsing for unverified users; show a banner instead

  // Dedicated video route: /video/:id (numeric or UUID)
  const m = path.match(/^\/video\/([A-Za-z0-9-]+)$/);
  if (m) {
    return <VideoPage videoId={m[1]} navigate={navigate} />;
  }

  return (
    <>
      <MainApp navigate={navigate} />
      {user && !user.age_verified && (
        <div className="approval-banner">
          <p>Age verification pending. You can browse publicly available videos, but some actions may be restricted.</p>
          <button onClick={() => logout && logout()}>Logout</button>
        </div>
      )}
      {user && showApprovalMessage && !user.is_approved && (
        <div className="approval-banner">
          <p>Your account is pending approval. You can view content but cannot upload videos yet.</p>
          <button onClick={() => setShowApprovalMessage(false)}>×</button>
        </div>
      )}
    </>
  );
};

export default App;