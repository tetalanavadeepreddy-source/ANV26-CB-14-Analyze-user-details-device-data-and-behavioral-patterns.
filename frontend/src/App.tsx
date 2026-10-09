import { useEffect, useState } from 'react'
import type { FormEvent } from 'react'
import { BrowserRouter, Link, Navigate, Outlet, Route, Routes, useLocation, useNavigate } from 'react-router-dom'
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  Boxes,
  Fingerprint,
  Gauge,
  GitBranch,
  LogOut,
  Search,
  ShieldCheck,
  ShieldEllipsis,
  UsersRound,
} from 'lucide-react'
import { authApi, dataApi, errorMessage } from './api'
import {
  BehaviorPage,
  DashboardPage,
  GraphPage,
  IdentitiesPage,
  InvestigationDetailPage,
  InvestigationsPage,
  ScenariosPage,
  TimelinePage,
  UserProfilePage,
} from './pages'
import './App.css'

const navigation = [
  { to: '/', label: 'Overview', icon: Gauge },
  { to: '/identities', label: 'Identities', icon: UsersRound },
  { to: '/investigations', label: 'Investigations', icon: ShieldEllipsis },
  { to: '/scenarios', label: 'Demo scenarios', icon: Boxes },
]

function LoginPage() {
  const [mode, setMode] = useState<'login' | 'register'>('login')
  const [email, setEmail] = useState('')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const navigate = useNavigate()
  const location = useLocation()

  if (authApi.isAuthenticated()) return <Navigate to="/" replace />

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setError('')
    setLoading(true)
    try {
      if (mode === 'register') await authApi.register(username.trim(), email.trim(), password)
      else await authApi.login(email.trim(), password)
      const destination = (location.state as { from?: string } | null)?.from ?? '/'
      navigate(destination, { replace: true })
    } catch (requestError) {
      setError(errorMessage(requestError))
    } finally {
      setLoading(false)
    }
  }

  return (
    <main className="auth-screen">
      <div className="auth-grid" aria-hidden="true" />
      <section className="auth-story">
        <Link className="brand-lockup" to="/login">
          <span className="brand-mark"><Fingerprint size={22} strokeWidth={1.8} /></span>
          <span>IDENTITYGUARD<span className="brand-x">-X</span></span>
        </Link>
        <div className="auth-story-copy">
          <span className="eyebrow"><span className="live-dot" /> IDENTITY RISK INTELLIGENCE</span>
          <h1>Trust is a signal.<br /><em>See the pattern.</em></h1>
          <p>Investigate connected identities, surface explainable risk, and move from signal to decision with evidence.</p>
        </div>
        <div className="auth-story-foot"><span>01 / 03</span><span className="story-rule" /><span>Explainable identity defense</span></div>
      </section>

      <section className="auth-panel">
        <div className="auth-panel-top"><span>SECURE ANALYST ACCESS</span><span><ShieldCheck size={15} /> TLS SESSION</span></div>
        <div className="auth-form-wrap">
          <div className="auth-form-icon"><ShieldCheck size={23} /></div>
          <p className="eyebrow">WELCOME TO THE CONTROL ROOM</p>
          <h2>{mode === 'login' ? 'Sign in' : 'Create account'}</h2>
          <p className="muted auth-description">{mode === 'login' ? 'Use your account credentials to continue.' : 'New accounts receive standard access. Analyst permissions are provisioned separately.'}</p>
          <form onSubmit={submit} className="auth-form">
            {mode === 'register' && (
              <label>Username<input autoComplete="username" required value={username} onChange={(event) => setUsername(event.target.value)} placeholder="analyst-name" /></label>
            )}
            <label>Email address<input type="email" autoComplete="email" required value={email} onChange={(event) => setEmail(event.target.value)} placeholder="analyst@organization.com" /></label>
            <label>Password<input type="password" autoComplete={mode === 'login' ? 'current-password' : 'new-password'} minLength={8} required value={password} onChange={(event) => setPassword(event.target.value)} placeholder="At least 8 characters" /></label>
            {error && <div className="inline-error"><AlertTriangle size={16} />{error}</div>}
            <button className="button button-primary auth-submit" type="submit" disabled={loading}>
              {loading ? <span className="spinner" /> : <>{mode === 'login' ? 'Sign in to workspace' : 'Create account'}<ArrowRight size={17} /></>}
            </button>
          </form>
          <div className="auth-switch">
            <span>{mode === 'login' ? 'New to IdentityGuard-X?' : 'Already have an account?'}</span>
            <button type="button" onClick={() => { setMode(mode === 'login' ? 'register' : 'login'); setError('') }}>
              {mode === 'login' ? 'Create account' : 'Sign in'}
            </button>
          </div>
        </div>
        <div className="auth-panel-foot"><span>IDENTITYGUARD-X // ANALYST CONSOLE</span><span>v0.1.0</span></div>
      </section>
    </main>
  )
}

function RequireAuth() {
  const location = useLocation()
  if (!authApi.isAuthenticated()) return <Navigate to="/login" replace state={{ from: location.pathname }} />
  return <Workspace />
}

function Workspace() {
  const [backendOnline, setBackendOnline] = useState<boolean | null>(null)
  const [search, setSearch] = useState('')
  const navigate = useNavigate()
  const location = useLocation()
  const account = authApi.currentUser()
  const active = navigation.find((item) => item.to === location.pathname)

  useEffect(() => {
    let alive = true
    dataApi.health().then(() => alive && setBackendOnline(true)).catch(() => alive && setBackendOnline(false))
    return () => { alive = false }
  }, [])

  function submitSearch(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    navigate(`/identities?search=${encodeURIComponent(search.trim())}`)
  }

  async function logout() {
    await authApi.logout()
    navigate('/login', { replace: true })
  }

  return (
    <div className="workspace">
      <aside className="sidebar">
        <Link className="brand-lockup sidebar-brand" to="/">
          <span className="brand-mark"><Fingerprint size={21} strokeWidth={1.8} /></span>
          <span>IDENTITYGUARD<span className="brand-x">-X</span></span>
        </Link>
        <div className="workspace-label">INVESTIGATION WORKSPACE</div>
        <nav className="side-nav" aria-label="Main navigation">
          {navigation.map(({ to, label, icon: Icon }) => (
            <Link key={to} to={to} className={`nav-link ${active?.to === to ? 'active' : ''}`}>
              <Icon size={18} strokeWidth={1.8} /><span>{label}</span>
              {to === '/investigations' && <span className="nav-trailing"><GitBranch size={14} /></span>}
            </Link>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="signal-panel">
            <div className="signal-panel-head"><Activity size={15} /><span>API CONNECTION</span></div>
            <div className="signal-panel-status"><span className={`status-dot ${backendOnline ? 'online' : backendOnline === false ? 'offline' : ''}`} />{backendOnline ? 'Connected' : backendOnline === false ? 'Unavailable' : 'Checking...'}</div>
            <span className="signal-panel-url">127.0.0.1:8000</span>
          </div>
          <div className="analyst-row">
            <div className="analyst-avatar">{account?.username?.slice(0, 1).toUpperCase() ?? 'A'}</div>
            <div className="analyst-meta"><strong>{account?.username ?? 'Analyst'}</strong><span>{account?.role ?? 'USER'}</span></div>
            <button className="icon-button logout-button" title="Sign out" aria-label="Sign out" onClick={() => void logout()}><LogOut size={16} /></button>
          </div>
        </div>
      </aside>

      <div className="workspace-main">
        <header className="topbar">
          <div className="breadcrumb"><span>IDENTITYGUARD-X</span><span className="breadcrumb-slash">/</span><strong>{active?.label ?? 'IDENTITY PROFILE'}</strong></div>
          <form className="global-search" onSubmit={submitSearch}>
            <Search size={16} /><input value={search} onChange={(event) => setSearch(event.target.value)} aria-label="Search identities" placeholder="Search identities" /><kbd>↵</kbd>
          </form>
          <div className="topbar-right"><span className="secure-label"><ShieldCheck size={14} /> SECURE SESSION</span></div>
        </header>
        <main className="page-content">
          <Outlet />
        </main>
        <footer className="workspace-footer"><span>IDENTITYGUARD-X · EXPLAINABLE SYNTHETIC IDENTITY RISK DETECTION</span><span>DATA SOURCED FROM ACTIVE BACKEND</span></footer>
      </div>
    </div>
  )
}

function AppRoutes() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route element={<RequireAuth />}>
        <Route index element={<DashboardPage />} />
        <Route path="/identities" element={<IdentitiesPage />} />
        <Route path="/users/:userId" element={<UserProfilePage />} />
        <Route path="/users/:userId/behavior" element={<BehaviorPage />} />
        <Route path="/users/:userId/timeline" element={<TimelinePage />} />
        <Route path="/users/:userId/graph" element={<GraphPage />} />
        <Route path="/investigations" element={<InvestigationsPage />} />
        <Route path="/investigations/:investigationId" element={<InvestigationDetailPage />} />
        <Route path="/scenarios" element={<ScenariosPage />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}

export default function App() {
  return <BrowserRouter><AppRoutes /></BrowserRouter>
}