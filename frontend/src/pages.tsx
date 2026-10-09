import { useEffect, useMemo, useRef, useState } from 'react'
import type { FormEvent } from 'react'
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom'
import cytoscape from 'cytoscape'
import type { Core } from 'cytoscape'
import {
  Activity,
  AlertCircle,
  ArrowRight,
  ArrowUpRight,
  Check,
  ChevronRight,
  CircleHelp,
  Clock3,
  Eye,
  Fingerprint,
  GitBranch,
  Layers3,
  LoaderCircle,
  Network,
  RefreshCw,
  Search,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  UserRound,
  UsersRound,
  Waypoints,
} from 'lucide-react'
import { authApi, dataApi, errorMessage } from './api'
import type {
  AnalysisResult,
  BehaviorEvent,
  DashboardSummary,
  DemoScenario,
  FeatureVector,
  GraphNode,
  IdentityChange,
  IdentityUser,
  Investigation,
  ModelMetrics,
  ObservationHistory,
  ObservationRecord,
  RiskIndicator,
} from './api'
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'

const riskColors: Record<string, string> = { LOW: '#47c99b', MEDIUM: '#f4b544', HIGH: '#ff6a68', CRITICAL: '#d84448' }

function PageHeading({ eyebrow, title, description, action }: { eyebrow: string; title: string; description?: string; action?: React.ReactNode }) {
  return <div className="page-heading"><div><div className="eyebrow">{eyebrow}</div><h1>{title}</h1>{description && <p className="muted">{description}</p>}</div>{action && <div className="heading-action">{action}</div>}</div>
}

function RiskBadge({ level }: { level: string | null | undefined }) {
  if (!level) return <span className="badge badge-neutral">NOT ANALYZED</span>
  const normalized = level.toUpperCase()
  return <span className={`badge badge-${normalized.toLowerCase()}`}><span className="badge-dot" />{normalized}</span>
}

function StatusBadge({ value }: { value: string }) {
  return <span className={`status-badge status-${value.toLowerCase().replaceAll('_', '-')}`}>{value.replaceAll('_', ' ')}</span>
}

function EmptyState({ icon = <Fingerprint size={20} />, title, detail, action }: { icon?: React.ReactNode; title: string; detail: string; action?: React.ReactNode }) {
  return <div className="empty-state"><div className="empty-icon">{icon}</div><strong>{title}</strong><p>{detail}</p>{action}</div>
}

function LoadingState({ label = 'Loading backend data...' }: { label?: string }) {
  return <div className="loading-state"><LoaderCircle className="spin" size={19} />{label}</div>
}

function RequestError({ message, retry }: { message: string; retry?: () => void }) {
  return <div className="request-error"><AlertCircle size={18} /><span>{message}</span>{retry && <button className="button button-quiet button-small" onClick={retry}><RefreshCw size={14} /> Retry</button>}</div>
}

function MetricCard({ label, value, note, tone = 'neutral', icon, to }: { label: string; value: string | number; note: string; tone?: string; icon: React.ReactNode; to?: string }) {
  const content = <><div className={`metric-icon metric-${tone}`}>{icon}</div><div className="metric-label">{label}</div><div className="metric-value">{value}</div><div className="metric-note">{note}</div></>
  return to ? <Link to={to} className={`metric-card metric-link metric-card-${tone}`}>{content}<ArrowUpRight className="metric-arrow" size={15} /></Link> : <div className={`metric-card metric-card-${tone}`}>{content}</div>
}

function SectionTitle({ title, detail, action }: { title: string; detail?: string; action?: React.ReactNode }) {
  return <div className="section-title"><div><h2>{title}</h2>{detail && <p>{detail}</p>}</div>{action}</div>
}

function formatDate(value?: string) {
  if (!value) return '—'
  const date = new Date(value)
  return Number.isNaN(date.valueOf()) ? '—' : new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(date)
}

function formatCompactDate(value: string) {
  return new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric' }).format(new Date(value))
}

export function DashboardPage() {
  const canViewObservations = ['ADMIN', 'ANALYST'].includes(authApi.currentUser()?.role.toUpperCase() ?? '')
  const [summary, setSummary] = useState<DashboardSummary | null>(null)
  const [distribution, setDistribution] = useState<{ level: string; count: number }[]>([])
  const [alerts, setAlerts] = useState<any[]>([])
  const [topIndicators, setTopIndicators] = useState<{ indicator_type: string; count: number }[]>([])
  const [investigations, setInvestigations] = useState<Investigation[]>([])
  const [observations, setObservations] = useState<ObservationRecord[]>([])
  const [trend, setTrend] = useState<any[]>([])
  const [modelMetrics, setModelMetrics] = useState<ModelMetrics | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const navigate = useNavigate()

  async function load() {
    setLoading(true)
    setError('')
    try {
      const [summaryData, distributionData, alertData, indicatorData, investigationData, assessments, observationData, metricsData] = await Promise.all([
        dataApi.summary(), dataApi.riskDistribution(), dataApi.recentAlerts(), dataApi.topIndicators(), dataApi.investigations(), dataApi.assessments(),
        canViewObservations ? dataApi.observations() : Promise.resolve([]),
        dataApi.modelMetrics(),
      ])
      setSummary(summaryData)
      setDistribution(distributionData)
      setAlerts(alertData)
      setTopIndicators(indicatorData)
      setInvestigations(investigationData.slice(0, 5))
      setObservations(observationData)
      setModelMetrics(metricsData)
      const byDay = new Map<string, { count: number; total: number }>()
      assessments.forEach((assessment: any) => {
        const day = formatCompactDate(assessment.created_at)
        const current = byDay.get(day) ?? { count: 0, total: 0 }
        current.count += 1
        current.total += Number(assessment.risk_score)
        byDay.set(day, current)
      })
      setTrend([...byDay.entries()].slice(-10).map(([date, value]) => ({ date, score: Math.round(value.total / value.count), assessments: value.count })))
    } catch (requestError) {
      setError(errorMessage(requestError))
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { void load() }, [])

  if (loading) return <LoadingState label="Loading live identity risk data..." />
  if (error) return <><PageHeading eyebrow="SECURITY OPERATIONS / OVERVIEW" title="Risk overview" description="Live identity signals and investigation workload." /><RequestError message={error} retry={() => void load()} /></>
  const hasAnalyses = Boolean(summary?.analyzed_users)
  const totals = distribution.reduce((sum, entry) => sum + entry.count, 0)

  return <>
    <PageHeading
      eyebrow="SECURITY OPERATIONS / OVERVIEW"
      title="Risk overview"
      description="Explainable identity signals across your active investigation workspace."
      action={<button className="button button-quiet" onClick={() => void load()}><RefreshCw size={15} /> Refresh data</button>}
    />
    {summary?.total_users === 0 && <div className="notice notice-info"><ShieldCheck size={18} /><div><strong>No identities analyzed yet</strong><span>The database is empty. Load a real demo scenario or register an identity to begin.</span></div><Link className="button button-secondary button-small" to="/scenarios">Load scenario <ArrowRight size={14} /></Link></div>}
    {summary && summary.total_users > 0 && !hasAnalyses && <div className="notice notice-info"><CircleHelp size={18} /><div><strong>No identities analyzed yet</strong><span>{summary.total_users} identities are in the database, but no risk assessments have been run.</span></div><Link className="button button-secondary button-small" to="/identities">Choose identity <ArrowRight size={14} /></Link></div>}
    <div className="metric-grid">
      <MetricCard label="Total identities" value={summary?.total_users ?? 0} note="Records in the identity store" icon={<UsersRound size={18} />} tone="cyan" to="/identities" />
      <MetricCard label="High risk" value={summary?.high_risk ?? 0} note="Latest saved assessments" icon={<ShieldAlert size={18} />} tone="red" to="/identities?risk=HIGH" />
      <MetricCard label="Critical alerts" value={summary?.critical_risk ?? 0} note="Latest saved assessments" icon={<ShieldAlert size={18} />} tone="red" to="/identities?risk=CRITICAL" />
      <MetricCard label="Medium risk" value={summary?.medium_risk ?? 0} note="Latest saved assessments" icon={<Activity size={18} />} tone="amber" to="/identities?risk=MEDIUM" />
      <MetricCard label="Low risk" value={summary?.low_risk ?? 0} note="Latest saved assessments" icon={<ShieldCheck size={18} />} tone="green" to="/identities?risk=LOW" />
      <MetricCard label="Active sessions" value={summary?.active_sessions ?? 0} note="Observed in the last hour" icon={<Activity size={18} />} tone="cyan" />
      <MetricCard label="Suspicious devices" value={summary?.suspicious_devices ?? 0} note="Linked to high-risk identities" icon={<Fingerprint size={18} />} tone="amber" />
      <MetricCard label="Suspicious IPs" value={summary?.suspicious_ips ?? 0} note="Flagged reputation or proxy signals" icon={<Network size={18} />} tone="red" />
      <MetricCard label="Fraud clusters" value={summary?.fraud_clusters ?? 0} note="Connected groups with high-risk users" icon={<Waypoints size={18} />} tone="violet" />
      {canViewObservations && <MetricCard label="Observation Cell" value={observations.length} note="Active accounts under observation" icon={<Eye size={18} />} tone="amber" />}
      <MetricCard label="Open investigations" value={summary?.open_investigations ?? 0} note="Open, review, or verification" icon={<GitBranch size={18} />} tone="violet" to="/investigations" />
    </div>

    {modelMetrics?.metrics && <section className="panel model-metrics-panel">
      <SectionTitle title="Model evaluation" detail={`${modelMetrics.metrics.model_version} · trained ${formatDate(modelMetrics.metrics.trained_at)} · ${modelMetrics.metrics.dataset_size.toLocaleString()} synthetic samples`} />
      <div className="model-metrics-grid">
        {[
          ['Accuracy', modelMetrics.metrics.accuracy], ['Precision', modelMetrics.metrics.precision],
          ['Recall', modelMetrics.metrics.recall], ['F1', modelMetrics.metrics.f1], ['ROC-AUC', modelMetrics.metrics.roc_auc],
        ].map(([label, value]) => <div className="model-metric" key={String(label)}><span>{label}</span><strong>{(Number(value) * 100).toFixed(1)}%</strong></div>)}
        <div className="model-confusion"><span>CONFUSION MATRIX · ACTUAL ROW / PREDICTED COLUMN</span><strong>{modelMetrics.metrics.confusion_matrix.map((row) => `[${row.join(', ')}]`).join(' ')}</strong></div>
      </div>
      <div className="feature-importance-list"><span>TRAINING-SET FEATURE IMPORTANCE</span>{modelMetrics.top_features.slice(0, 5).map((feature) => <div className="feature-importance-row" key={feature.feature}><span>{feature.feature.replaceAll('_', ' ')}</span><div><i style={{ width: `${Math.min(100, feature.importance * 500)}%` }} /></div><strong>{(feature.importance * 100).toFixed(1)}%</strong></div>)}</div>
      <p className="synthetic-warning">Synthetic/test performance only. It does not estimate real-world fraud accuracy or prevalence.</p>
    </section>}

    {canViewObservations && <section className="panel table-panel observation-panel">
      <SectionTitle title="Observation Cell" detail={`${observations.length} active accounts · MEDIUM, HIGH, or CRITICAL risk`} />
      {!observations.length ? <EmptyState icon={<Eye size={20} />} title="No accounts under observation" detail="MEDIUM, HIGH, and CRITICAL risk accounts appear here automatically after analysis." /> : <div className="table-scroll"><table><thead><tr><th>Account</th><th>User ID</th><th>Risk score</th><th>Level</th><th>Observed since</th><th>Main reasons</th><th>Status</th></tr></thead><tbody>{observations.map((observation) => <tr key={observation.id} onClick={() => navigate(`/users/${observation.user_id}`)}><td><strong>{observation.username}</strong></td><td className="mono">#{observation.user_id}</td><td className="mono">{Number(observation.risk_score).toFixed(1)}</td><td><RiskBadge level={observation.risk_level} /></td><td className="muted">{formatDate(observation.started_at)}</td><td className="observation-reasons">{observation.reasons.join('; ') || 'No indicator details available'}</td><td><StatusBadge value={observation.status} /></td></tr>)}</tbody></table></div>}
    </section>}

    <div className="dashboard-grid dashboard-grid-top">
      <section className="panel chart-panel">
        <SectionTitle title="Risk distribution" detail="Latest saved assessment per analyzed identity" />
        {totals === 0 ? <EmptyState icon={<Activity size={20} />} title="No risk distribution yet" detail="Run an analysis to populate these values from saved backend assessments." /> : <div className="distribution-layout">
          <div className="donut-wrap"><ResponsiveContainer width="100%" height="100%"><PieChart><Pie data={distribution} dataKey="count" nameKey="level" innerRadius="69%" outerRadius="90%" paddingAngle={3} stroke="none">{distribution.map((item) => <Cell key={item.level} fill={riskColors[item.level] ?? '#70808b'} />)}</Pie><Tooltip contentStyle={{ background: '#151e22', border: '1px solid #2b393e', borderRadius: 4, color: '#eef4f3' }} /></PieChart></ResponsiveContainer><div className="donut-center"><strong>{totals}</strong><span>ANALYZED</span></div></div>
          <div className="distribution-legend">{distribution.map((item) => <div className="legend-row" key={item.level}><span className="legend-swatch" style={{ background: riskColors[item.level] }} /><span>{item.level}</span><strong>{item.count}</strong></div>)}</div>
        </div>}
      </section>
      <section className="panel chart-panel trend-panel">
        <SectionTitle title="Risk trend" detail="Average assessment score by assessment date" />
        {trend.length < 2 ? <EmptyState icon={<Activity size={20} />} title="Trend needs more data" detail="A trend appears after assessments are recorded on multiple dates." /> : <div className="trend-chart"><ResponsiveContainer width="100%" height="100%"><LineChart data={trend} margin={{ top: 12, right: 8, bottom: 0, left: -22 }}><CartesianGrid stroke="#243137" vertical={false} /><XAxis dataKey="date" tick={{ fill: '#829298', fontSize: 11 }} axisLine={false} tickLine={false} /><YAxis domain={[0, 100]} tick={{ fill: '#829298', fontSize: 11 }} axisLine={false} tickLine={false} /><Tooltip contentStyle={{ background: '#151e22', border: '1px solid #2b393e', borderRadius: 4, color: '#eef4f3' }} /><Line type="monotone" dataKey="score" stroke="#50c4c6" strokeWidth={2} dot={{ fill: '#50c4c6', r: 3 }} activeDot={{ r: 5 }} /></LineChart></ResponsiveContainer></div>}
      </section>
    </div>

    <div className="dashboard-grid dashboard-grid-bottom">
      <section className="panel table-panel">
        <SectionTitle title="Recent risk alerts" detail="Most recent saved identity assessments" action={<Link className="text-link" to="/identities">All identities <ChevronRight size={15} /></Link>} />
        {!alerts.length ? <EmptyState icon={<ShieldCheck size={20} />} title="No identities analyzed yet" detail="New alerts appear here after an analyst runs an identity analysis." action={<Link className="button button-secondary button-small" to="/identities">Browse identities</Link>} /> : <div className="table-scroll"><table><thead><tr><th>Identity</th><th>Risk</th><th>Score</th><th>Assessed</th><th /></tr></thead><tbody>{alerts.map((alert) => <tr key={alert.id} onClick={() => navigate(`/users/${alert.user_id}`)}><td><span className="identity-cell"><span className="table-avatar"><UserRound size={15} /></span><span><strong>{alert.username}</strong><small>{alert.email}</small></span></span></td><td><RiskBadge level={alert.risk_level} /></td><td><strong className="mono">{Number(alert.risk_score).toFixed(1)}</strong></td><td className="muted">{formatDate(alert.created_at)}</td><td><ChevronRight size={16} className="row-chevron" /></td></tr>)}</tbody></table></div>}
      </section>
      <section className="panel indicators-panel">
        <SectionTitle title="Top risk indicators" detail="Persisted explanations across analyses" />
        {!topIndicators.length ? <EmptyState icon={<Sparkles size={19} />} title="No indicators recorded" detail="Indicators will be summarized after identities are analyzed." /> : <div className="indicator-rank-list">{topIndicators.map((indicator, index) => <div className="indicator-rank" key={indicator.indicator_type}><span className="indicator-rank-number">0{index + 1}</span><span className="indicator-rank-name">{indicator.indicator_type.replaceAll('_', ' ')}</span><strong>{indicator.count}</strong></div>)}</div>}
      </section>
    </div>

    <section className="panel investigations-preview">
      <SectionTitle title="Recent investigations" detail="Analyst case queue" action={<Link className="text-link" to="/investigations">Open center <ChevronRight size={15} /></Link>} />
      {!investigations.length ? <div className="compact-empty">No investigations have been opened.</div> : <div className="investigation-preview-list">{investigations.map((investigation) => <Link className="investigation-preview-row" to={`/investigations/${investigation.id}`} key={investigation.id}><span className="case-id">CASE-{String(investigation.id).padStart(4, '0')}</span><strong>{investigation.username}</strong><RiskBadge level={investigation.risk_level} /><StatusBadge value={investigation.status} /><span className="preview-date">{formatDate(investigation.updated_at)}</span><ChevronRight size={15} /></Link>)}</div>}
    </section>
  </>
}

export function IdentitiesPage() {
  const [params, setParams] = useSearchParams()
  const [search, setSearch] = useState(params.get('search') ?? '')
  const [users, setUsers] = useState<IdentityUser[]>([])
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const navigate = useNavigate()

  const riskFilter = params.get('risk') ?? ''

  async function load(query = search, risk = riskFilter) {
    setLoading(true)
    setError('')
    try { setUsers(await dataApi.users(query, risk)) } catch (requestError) { setError(errorMessage(requestError)) } finally { setLoading(false) }
  }

  useEffect(() => {
    const query = params.get('search') ?? ''
    setSearch(query)
    void load(query, params.get('risk') ?? '')
  }, [params])

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setParams({ ...(search.trim() ? { search: search.trim() } : {}), ...(riskFilter ? { risk: riskFilter } : {}) })
  }

  return <>
    <PageHeading eyebrow="IDENTITY INTELLIGENCE / DIRECTORY" title="Identity search" description="Search by numeric user ID, username, or email address." action={<span className="record-count">{users.length} RECORDS</span>} />
    <section className="panel identity-search-panel">
      <form className="directory-search" onSubmit={submit}><Search size={18} /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Enter user ID, username, or email" autoFocus /><button className="button button-primary" type="submit">Search identities</button></form>
      <div className="filter-note"><span>{riskFilter ? `LATEST ${riskFilter} ASSESSMENTS` : 'QUERY MATCH'}</span><span>ID · USERNAME · EMAIL</span><span>MAX 100 RESULTS</span></div>
    </section>
    {error && <RequestError message={error} retry={() => void load()} />}
    {loading ? <LoadingState /> : users.length === 0 ? <section className="panel"><EmptyState icon={<UsersRound size={20} />} title={search ? 'No matching identities' : 'No identities in the database'} detail={search ? 'Try a different ID, username, or email.' : 'Generate a real demo scenario or register a user to start investigating.'} action={<Link to="/scenarios" className="button button-secondary button-small">Open demo scenarios <ArrowRight size={14} /></Link>} /></section> : <section className="panel table-panel directory-table-panel"><div className="table-scroll"><table><thead><tr><th>Identity</th><th>User ID</th><th>Verification</th><th>Latest risk</th><th>Account created</th><th>Status</th><th /></tr></thead><tbody>{users.map((user) => <tr key={user.id} onClick={() => navigate(`/users/${user.id}`)}><td><span className="identity-cell"><span className="table-avatar"><UserRound size={15} /></span><span><strong>{user.username}</strong><small>{user.email}</small></span></span></td><td className="mono">#{user.id}</td><td><StatusBadge value={user.identity_verification_status} /></td><td><RiskBadge level={user.risk_score > 0 ? user.risk_level : null} /></td><td className="muted">{formatDate(user.created_at)}</td><td><StatusBadge value={user.status} /></td><td><ChevronRight size={16} className="row-chevron" /></td></tr>)}</tbody></table></div></section>}
  </>
}

function ProfileTabs({ userId, current }: { userId: number; current: string }) {
  const tabs = [{ key: 'profile', label: 'Risk profile', href: `/users/${userId}` }, { key: 'behavior', label: 'Behaviour', href: `/users/${userId}/behavior` }, { key: 'timeline', label: 'Timeline', href: `/users/${userId}/timeline` }, { key: 'graph', label: 'Relationship graph', href: `/users/${userId}/graph` }]
  return <div className="profile-tabs">{tabs.map((tab) => <Link key={tab.key} to={tab.href} className={current === tab.key ? 'selected' : ''}>{tab.label}</Link>)}</div>
}

function RiskDial({ score, level }: { score: number; level: string }) {
  const color = riskColors[level] ?? '#62737b'
  return <div className="risk-dial" style={{ background: `conic-gradient(${color} ${Math.max(0, Math.min(100, score)) * 3.6}deg, #26343a 0deg)` }}><div className="risk-dial-inner"><strong>{score.toFixed(1)}</strong><span>/ 100</span></div></div>
}

function ObservationDetailsPanel({ observation, userId }: { observation: ObservationHistory; userId: number }) {
  const active = observation.active_observation
  if (!observation.history.length) return null
  return <section className="panel observation-detail-panel">
    <SectionTitle title="Observation Cell" detail={active ? 'Current review and application activity' : 'Previous observation episodes'} />
    {active && <>
      <div className="observation-detail-facts">
        <div><span>RISK SCORE</span><strong>{active.risk_score.toFixed(1)}</strong></div>
        <div><span>RISK LEVEL</span><RiskBadge level={active.risk_level} /></div>
        <div><span>OBSERVED SINCE</span><strong>{formatDate(active.started_at)}</strong></div>
        <div><span>CURRENT STATUS</span><StatusBadge value={active.status} /></div>
      </div>
      <div className="observation-detail-columns">
        <div><h3>Reasons</h3>{active.reasons.length ? <ul>{active.reasons.map((reason) => <li key={reason}>{reason}</li>)}</ul> : <p className="muted">No indicator details available.</p>}</div>
        <div><h3>Linked devices and networks</h3>{active.devices?.length ? active.devices.map((device) => <p key={device.id}>Device {device.id} · {device.device_type} · {device.operating_system} · {device.browser}</p>) : <p className="muted">No linked devices.</p>}{active.networks?.length ? active.networks.map((network, index) => <p key={`${network.country}-${index}`}>Network · {[network.country, network.region, network.isp].filter(Boolean).join(' · ')}</p>) : <p className="muted">No linked network details.</p>}<Link className="text-link" to={`/users/${userId}/graph`}>View connected accounts <ArrowRight size={14} /></Link></div>
      </div>
      <div className="observation-activity">
        <h3>Activity history</h3>
        {!active.activities?.length ? <p className="muted">No application activity has been recorded during this episode.</p> : <ol>{active.activities.map((activity) => <li key={activity.id}><time>{formatDate(activity.timestamp)}</time><strong>{activity.activity_type.replaceAll('_', ' ')}</strong>{activity.details && <span>{activity.details}</span>}</li>)}</ol>}
      </div>
    </>}
    <div className="observation-episodes">{observation.history.map((episode) => <div key={episode.id}><span>{formatDate(episode.started_at)}</span><RiskBadge level={episode.risk_level} /><StatusBadge value={episode.status} /><span>{episode.reasons.join('; ') || 'No indicator details available'}</span>{episode.id !== active?.id && episode.activities?.map((activity) => <span className="observation-episode-activity" key={activity.id}>{formatDate(activity.timestamp)} · {activity.activity_type.replaceAll('_', ' ')}{activity.details ? ` · ${activity.details}` : ''}</span>)}</div>)}</div>
  </section>
}

export function UserProfilePage() {
  const canViewObservations = ['ADMIN', 'ANALYST'].includes(authApi.currentUser()?.role.toUpperCase() ?? '')
  const { userId: rawId } = useParams()
  const userId = Number(rawId)
  const navigate = useNavigate()
  const [user, setUser] = useState<IdentityUser | null>(null)
  const [risk, setRisk] = useState<any>(null)
  const [features, setFeatures] = useState<FeatureVector | null>(null)
  const [indicators, setIndicators] = useState<RiskIndicator[]>([])
  const [graph, setGraph] = useState<{ nodes: GraphNode[]; edges: any[] } | null>(null)
  const [observation, setObservation] = useState<ObservationHistory | null>(null)
  const [analysis, setAnalysis] = useState<AnalysisResult | null>(null)
  const [loading, setLoading] = useState(true)
  const [analyzing, setAnalyzing] = useState(false)
  const [feedbackSending, setFeedbackSending] = useState(false)
  const [error, setError] = useState('')
  const [actionMessage, setActionMessage] = useState('')

  async function load() {
    setLoading(true)
    setError('')
    try {
      const [userData, riskData, featureData, indicatorData, graphData, observationData] = await Promise.all([
        dataApi.user(userId), dataApi.risk(userId), dataApi.features(userId), dataApi.indicators(userId), dataApi.graph(userId),
        canViewObservations ? dataApi.observationHistory(userId) : Promise.resolve(null),
      ])
      setUser(userData)
      setRisk(riskData)
      setFeatures(featureData)
      setIndicators(indicatorData)
      setGraph(graphData)
      setObservation(observationData)
      setAnalysis(null)
    } catch (requestError) { setError(errorMessage(requestError)) } finally { setLoading(false) }
  }

  useEffect(() => { if (Number.isInteger(userId)) void load() }, [userId])

  async function analyze() {
    setAnalyzing(true)
    setError('')
    setActionMessage('')
    try {
      const result = await dataApi.analyze(userId)
      setAnalysis(result)
      setRisk({ analyzed: true, risk_score: result.risk_score, risk_level: result.risk_level, assessment: result })
      setIndicators(result.indicators)
      if (canViewObservations) setObservation(await dataApi.observationHistory(userId))
      if (user) setUser({ ...user, risk_score: result.risk_score, risk_level: result.risk_level })
    } catch (requestError) { setError(errorMessage(requestError)) } finally { setAnalyzing(false) }
  }

  async function openCase() {
    try {
      const result = await dataApi.openInvestigation(userId)
      navigate(`/investigations/${result.id}`)
    } catch (requestError) { setError(errorMessage(requestError)) }
  }

  async function requestVerification() {
    try {
      await dataApi.requestVerification(userId)
      setActionMessage('Verification has been requested and the identity is marked for follow-up.')
      await load()
    } catch (requestError) { setError(errorMessage(requestError)) }
  }

  async function submitFeedback(action: 'CONFIRM_FRAUD' | 'FALSE_POSITIVE') {
    if (!analysis?.prediction_id) return
    setFeedbackSending(true)
    setError('')
    try {
      const result = await dataApi.predictionFeedback(analysis.prediction_id, action)
      setActionMessage(`${result.status}: ${action.replaceAll('_', ' ').toLowerCase()}.`)
    } catch (requestError) { setError(errorMessage(requestError)) } finally { setFeedbackSending(false) }
  }

  if (loading) return <LoadingState label="Loading identity evidence..." />
  if (error && !user) return <><PageHeading eyebrow="IDENTITY INTELLIGENCE" title="Identity profile" /><RequestError message={error} retry={() => void load()} /></>
  if (!user || !features) return <EmptyState title="Identity not found" detail="The requested user ID does not exist in the backend." action={<Link to="/identities" className="button button-secondary button-small">Return to identity search</Link>} />
  const isAnalyzed = Boolean(risk?.analyzed)
  const score = isAnalyzed ? Number(risk.risk_score) : 0
  const level = isAnalyzed ? String(risk.risk_level) : 'LOW'
  const deviceNodes = graph?.nodes.filter((node) => node.type === 'device') ?? []
  const ipNodes = graph?.nodes.filter((node) => node.type === 'ip') ?? []
  const displayedSignals = [
    ['Identity', analysis?.signal_scores.identity ?? risk?.assessment?.signal_scores?.identity ?? risk?.assessment?.rule_score ?? 0],
    ['Device', analysis?.signal_scores.device ?? risk?.assessment?.signal_scores?.device ?? 0],
    ['Network', analysis?.signal_scores.network ?? risk?.assessment?.signal_scores?.network ?? 0],
    ['Behavior', analysis?.signal_scores.behavior ?? risk?.assessment?.signal_scores?.behavior ?? risk?.assessment?.behavior_score ?? 0],
    ['Temporal', analysis?.signal_scores.temporal ?? risk?.assessment?.signal_scores?.temporal ?? 0],
    ['Graph', analysis?.signal_scores.graph ?? risk?.assessment?.signal_scores?.graph ?? risk?.assessment?.graph_score ?? 0],
    ['Supervised ML', analysis?.ml_score ?? risk?.assessment?.model_score ?? 0],
    ['Anomaly', analysis?.anomaly_score ?? risk?.assessment?.anomaly_score ?? 0],
  ] as const

  return <>
    <div className="profile-breadcrumb"><Link to="/identities">Identities</Link><ChevronRight size={14} /><span>{user.username}</span><span className="profile-user-id">USER-{String(user.id).padStart(5, '0')}</span></div>
    <PageHeading eyebrow="IDENTITY INTELLIGENCE / CASE SUBJECT" title={user.username} description={user.email} action={<><button className="button button-secondary" onClick={() => void openCase()}><GitBranch size={15} /> Open investigation</button><button className="button button-primary" onClick={() => void analyze()} disabled={analyzing}>{analyzing ? <><span className="spinner" /> Analyzing</> : <><Sparkles size={15} /> Analyze identity</>}</button></>} />
    <ProfileTabs userId={user.id} current="profile" />
    {error && <RequestError message={error} />}
    {actionMessage && <div className="notice notice-success"><Check size={17} /><div><strong>Request recorded</strong><span>{actionMessage}</span></div></div>}
    {canViewObservations && observation && <ObservationDetailsPanel observation={observation} userId={user.id} />}
    <div className="profile-overview-grid">
      <section className={`panel risk-summary-panel ${isAnalyzed ? `risk-summary-${level.toLowerCase()}` : ''}`}>
        <div className="risk-summary-heading"><div><div className="eyebrow">LATEST RISK ASSESSMENT</div><RiskBadge level={isAnalyzed ? level : null} /></div><span className="score-scale">0—100</span></div>
        {isAnalyzed ? <div className="risk-score-layout"><RiskDial score={score} level={level} /><div className="risk-decision"><span>DECISION</span><strong>{analysis?.decision ?? risk?.assessment?.decision ?? '—'}</strong><small>Evidence confidence {analysis?.confidence ?? risk?.assessment?.confidence ?? '—'}%</small><small>Evidence coverage {analysis?.evidence_coverage ?? risk?.assessment?.evidence_coverage ?? '—'}%</small><small>{formatDate(risk?.assessment?.created_at)}</small></div></div> : <div className="risk-empty"><div className="risk-dial risk-dial-empty"><div className="risk-dial-inner"><strong>—</strong><span>NOT SCORED</span></div></div><div><strong>No assessment yet</strong><p>Analyze this identity to calculate a score from its recorded evidence.</p></div></div>}
        <div className="signal-score-grid">{displayedSignals.map(([label, value]) => <div className="signal-score" key={label}><span>{label}</span><strong>{isAnalyzed ? `${Number(value).toFixed(1)}` : '—'}</strong></div>)}</div>
        {isAnalyzed && <div className="model-note"><CircleHelp size={14} /> {(analysis?.model_status ?? risk?.assessment?.model_status) === 'loaded' ? `${analysis?.model_version ?? risk?.assessment?.model_version} · supervised Random Forest and Isolation Forest loaded.` : 'Model artifacts unavailable; this assessment uses zero model contributions.'}</div>}
        {isAnalyzed && analysis?.prediction_id && <div className="feedback-actions"><span>INVESTIGATOR FEEDBACK</span><button className="button button-secondary button-small" onClick={() => void submitFeedback('CONFIRM_FRAUD')} disabled={feedbackSending}><ShieldAlert size={13} /> Confirm fraud</button><button className="button button-quiet button-small" onClick={() => void submitFeedback('FALSE_POSITIVE')} disabled={feedbackSending}><Check size={13} /> False positive</button></div>}
      </section>

      <section className="panel identity-details-panel">
        <SectionTitle title="Identity record" detail={`Account created ${formatDate(user.created_at)}`} />
        <div className="detail-grid">
          <div className="detail-item"><span>USER ID</span><strong>#{user.id}</strong></div>
          <div className="detail-item"><span>ACCOUNT AGE</span><strong>{features.account_age_days.toFixed(0)} days</strong></div>
          <div className="detail-item"><span>VERIFICATION</span><StatusBadge value={user.identity_verification_status} /></div>
          <div className="detail-item"><span>ACCOUNT STATUS</span><StatusBadge value={user.status} /></div>
          <div className="detail-item"><span>DEVICE LINKS</span><strong>{deviceNodes.length}</strong></div>
          <div className="detail-item"><span>NETWORK LINKS</span><strong>{ipNodes.length}</strong></div>
        </div>
        <div className="identity-record-actions"><Link to={`/users/${user.id}/graph`} className="text-link">View relationship graph <ArrowRight size={14} /></Link><button className="text-link-button" onClick={() => void requestVerification()}>Request verification</button></div>
      </section>
    </div>

    <div className="dashboard-grid profile-lower-grid">
      <section className="panel explain-panel">
        <SectionTitle title="Why is this identity risky?" detail="Explanations from the latest persisted assessment" />
        {!isAnalyzed || indicators.length === 0 ? <EmptyState icon={<Sparkles size={19} />} title={isAnalyzed ? 'No risk indicators found' : 'Run analysis to surface evidence'} detail={isAnalyzed ? 'No configured rule matched the observed identity features.' : 'No indicators are generated until a real analysis is run.'} /> : <>
          {analysis?.mitigating_reasons.map((reason) => <div className="notice notice-info risk-mitigation" key={reason}><ShieldCheck size={15} /><span>{reason}</span></div>)}
          <div className="indicator-cards">{analysis?.top_reasons.length ? analysis.top_reasons.map((reason) => <article className="indicator-card" key={`${reason.feature}-${reason.signal}`}><div className="indicator-card-top"><span className="indicator-type">{reason.signal} signal · {reason.feature.replaceAll('_', ' ')}</span><strong className="reason-points">+{reason.weighted_points.toFixed(1)}</strong></div><p>{reason.description}</p><div className="indicator-feature">MEASURED VALUE <strong>{String(reason.feature_value)}</strong></div></article>) : indicators.map((indicator, index) => <IndicatorCard indicator={indicator} key={`${indicator.indicator_type}-${index}`} />)}</div>
        </>}
      </section>
      <section className="panel behavior-summary-panel">
        <SectionTitle title="Behaviour summary" detail="Measured event and identity features" action={<Link className="text-link" to={`/users/${user.id}/behavior`}>Details <ChevronRight size={14} /></Link>} />
        <div className="behavior-summary-rows">
          <SummaryMetric label="Actions / minute" value={features.actions_per_minute.toFixed(2)} />
          <SummaryMetric label="Failed logins" value={features.failed_login_count} />
          <SummaryMetric label="Identity changes (24h)" value={features.identity_changes_last_24h} />
          <SummaryMetric label="Max linked device users" value={features.device_account_count} />
          <SummaryMetric label="Max linked network users" value={features.ip_account_count} />
        </div>
      </section>
    </div>
    <div className="dashboard-grid profile-links-grid">
      <section className="panel"><SectionTitle title="Linked devices" detail="Device records directly connected to this identity" />{!deviceNodes.length ? <div className="compact-empty">No device records are linked to this identity.</div> : <div className="linked-record-list">{deviceNodes.map((node) => <div className="linked-record" key={node.id}><span className="linked-record-icon"><Fingerprint size={15} /></span><span><strong>{node.label}</strong><small>{node.details}</small></span></div>)}</div>}</section>
      <section className="panel"><SectionTitle title="Network evidence" detail="Linked IP/network records and observed reputation" />{!ipNodes.length ? <div className="compact-empty">No network records are linked to this identity.</div> : <div className="linked-record-list">{ipNodes.map((node) => <div className="linked-record" key={node.id}><span className="linked-record-icon network"><Network size={15} /></span><span><strong>{node.label}</strong><small>{node.details}</small></span></div>)}</div>}</section>
    </div>
  </>
}

function IndicatorCard({ indicator }: { indicator: RiskIndicator }) {
  return <article className={`indicator-card severity-${indicator.severity.toLowerCase()}`}><div className="indicator-card-top"><RiskBadge level={indicator.severity === 'LOW' ? 'LOW' : indicator.severity} /><span className="indicator-type">{indicator.indicator_type.replaceAll('_', ' ')}</span></div><p>{indicator.description}</p><div className="indicator-feature">MEASURED VALUE <strong>{indicator.feature_value || '—'}</strong></div></article>
}

function SummaryMetric({ label, value }: { label: string; value: string | number }) {
  return <div className="summary-metric"><span>{label}</span><strong>{value}</strong></div>
}

export function BehaviorPage() {
  const { userId: rawId } = useParams()
  const userId = Number(rawId)
  const [features, setFeatures] = useState<FeatureVector | null>(null)
  const [events, setEvents] = useState<BehaviorEvent[]>([])
  const [user, setUser] = useState<IdentityUser | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let alive = true
    Promise.all([dataApi.features(userId), dataApi.events(userId), dataApi.user(userId)])
      .then(([featureData, eventData, userData]) => { if (alive) { setFeatures(featureData); setEvents(eventData.events); setUser(userData) } })
      .catch((requestError) => alive && setError(errorMessage(requestError)))
      .finally(() => alive && setLoading(false))
    return () => { alive = false }
  }, [userId])

  if (loading) return <LoadingState label="Loading observed behavior..." />
  if (error || !features || !user) return <RequestError message={error || 'Behavior data unavailable.'} />
  const logins = events.filter((event) => event.event_type === 'LOGIN').length
  const deviceChanges = events.filter((event) => event.event_type === 'DEVICE_CHANGE').length + features.device_change_count
  const eventCounts = [...events.reduce((map, event) => map.set(event.event_type, (map.get(event.event_type) ?? 0) + 1), new Map<string, number>()).entries()].map(([name, count]) => ({ name: name.replaceAll('_', ' '), count })).sort((a, b) => b.count - a.count).slice(0, 8)

  return <>
    <PageHeading eyebrow="IDENTITY INTELLIGENCE / BEHAVIOUR" title="Behaviour profile" description={`${user.username} · measured from ${events.length} recorded events`} action={<Link className="button button-secondary" to={`/users/${user.id}`}><Fingerprint size={15} /> Risk profile</Link>} />
    <ProfileTabs userId={user.id} current="behavior" />
    <div className="metric-grid behavior-metrics">
      <MetricCard label="Login events" value={logins} note="Recorded LOGIN events" icon={<UsersRound size={17} />} tone="cyan" />
      <MetricCard label="Failed logins" value={features.failed_login_count} note="Recorded FAILED_LOGIN events" icon={<ShieldAlert size={17} />} tone="red" />
      <MetricCard label="Actions / minute" value={features.actions_per_minute.toFixed(2)} note="Across the observed event window" icon={<Activity size={17} />} tone="amber" />
      <MetricCard label="Avg. session duration" value={`${features.average_session_duration.toFixed(1)}s`} note="Mean first-to-last event span per session" icon={<Clock3 size={17} />} tone="cyan" />
      <MetricCard label="Request velocity" value={`${features.request_velocity.toFixed(2)}/h`} note="Events in last 24h / 24" icon={<ArrowUpRight size={17} />} tone="violet" />
    </div>
    <div className="dashboard-grid behavior-grid">
      <section className="panel chart-panel"><SectionTitle title="Event activity" detail="Recorded event totals by type" />{eventCounts.length ? <div className="behavior-chart"><ResponsiveContainer width="100%" height="100%"><BarChart data={eventCounts} margin={{ top: 8, right: 8, bottom: 22, left: -18 }}><CartesianGrid stroke="#243137" vertical={false} /><XAxis dataKey="name" tick={{ fill: '#829298', fontSize: 10 }} axisLine={false} tickLine={false} angle={-18} textAnchor="end" /><YAxis tick={{ fill: '#829298', fontSize: 11 }} axisLine={false} tickLine={false} /><Tooltip contentStyle={{ background: '#151e22', border: '1px solid #2b393e', borderRadius: 4, color: '#eef4f3' }} /><Bar dataKey="count" fill="#50c4c6" radius={[3, 3, 0, 0]} /></BarChart></ResponsiveContainer></div> : <EmptyState title="No behavior events" detail="Behavior metrics will populate when event data is recorded." />}</section>
      <section className="panel"><SectionTitle title="Behavior signals" detail="Feature-engineered from backend event data" /><div className="behavior-summary-rows"><SummaryMetric label="Average action interval" value={`${features.average_action_interval.toFixed(1)}s`} /><SummaryMetric label="Request velocity" value={`${features.request_velocity.toFixed(2)} events/hour`} /><SummaryMetric label="Login burst (last hour)" value={features.login_burst_score} /><SummaryMetric label="Identity changes total" value={features.identity_change_count} /><SummaryMetric label="Identity changes / 24h" value={features.identity_changes_last_24h} /><SummaryMetric label="Device-change events" value={deviceChanges} /><SummaryMetric label="Sessions observed" value={new Set(events.map((event) => event.session_id)).size} /></div></section>
    </div>
  </>
}

type TimelineEntry = { id: string; title: string; detail: string; time: string; kind: string }

export function TimelinePage() {
  const { userId: rawId } = useParams()
  const userId = Number(rawId)
  const [user, setUser] = useState<IdentityUser | null>(null)
  const [timeline, setTimeline] = useState<{ behavior_events: BehaviorEvent[]; identity_changes: IdentityChange[] } | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let alive = true
    Promise.all([dataApi.user(userId), dataApi.timeline(userId)])
      .then(([userData, timelineData]) => { if (alive) { setUser(userData); setTimeline(timelineData) } })
      .catch((requestError) => alive && setError(errorMessage(requestError)))
      .finally(() => alive && setLoading(false))
    return () => { alive = false }
  }, [userId])

  if (loading) return <LoadingState label="Loading identity timeline..." />
  if (error || !user || !timeline) return <RequestError message={error || 'Timeline unavailable.'} />
  const entries: TimelineEntry[] = [
    { id: 'created', title: 'Account created', detail: `Identity ${user.username} was created`, time: user.created_at, kind: 'account' },
    ...timeline.behavior_events.map((event) => ({ id: `event-${event.id}`, title: event.event_type.replaceAll('_', ' '), detail: `Session ${event.session_id} · ${event.duration}s duration`, time: event.timestamp, kind: event.event_type.toLowerCase() })),
    ...timeline.identity_changes.map((change) => ({ id: `change-${change.id}`, title: `${change.field_changed} changed`, detail: 'Identity change recorded by backend', time: change.timestamp, kind: 'identity-change' })),
  ].sort((a, b) => new Date(b.time).valueOf() - new Date(a.time).valueOf())

  return <>
    <PageHeading eyebrow="IDENTITY INTELLIGENCE / EVENT HISTORY" title="Identity timeline" description={`${user.username} · ${entries.length} account, behavior, and identity-change records`} action={<Link className="button button-secondary" to={`/users/${user.id}`}><Fingerprint size={15} /> Risk profile</Link>} />
    <ProfileTabs userId={user.id} current="timeline" />
    {!entries.length ? <section className="panel"><EmptyState icon={<Clock3 size={20} />} title="No timeline activity" detail="Account creation, behavior, and identity changes will appear here when available." /></section> : <section className="panel timeline-panel"><div className="timeline-toolbar"><span>EVENT RECORD</span><span>{entries.length} ITEMS · NEWEST FIRST</span></div><div className="timeline-list">{entries.map((entry) => <article className="timeline-entry" key={entry.id}><div className={`timeline-marker marker-${entry.kind.includes('change') ? 'change' : entry.kind.includes('failed') ? 'failed' : entry.kind === 'account' ? 'account' : 'event'}`}><TimelineIcon kind={entry.kind} /></div><div className="timeline-body"><div className="timeline-heading"><strong>{entry.title}</strong><time>{formatDate(entry.time)}</time></div><p>{entry.detail}</p></div><span className="timeline-type">{entry.kind.replaceAll('-', ' ')}</span></article>)}</div></section>}
  </>
}

function TimelineIcon({ kind }: { kind: string }) {
  if (kind === 'account') return <UserRound size={15} />
  if (kind.includes('change')) return <RefreshCw size={14} />
  if (kind.includes('failed')) return <AlertCircle size={14} />
  if (kind.includes('login')) return <ShieldCheck size={14} />
  return <Activity size={14} />
}

function RelationshipCanvas({ nodes, edges, onSelect }: { nodes: GraphNode[]; edges: { source: string; target: string; label: string }[]; onSelect?: (node: GraphNode) => void }) {
  const container = useRef<HTMLDivElement | null>(null)
  const graphRef = useRef<Core | null>(null)
  const nodeMap = useMemo(() => new Map(nodes.map((node) => [node.id, node])), [nodes])

  useEffect(() => {
    if (!container.current || nodes.length === 0) return
    const graph = cytoscape({
      container: container.current,
      elements: [
        ...nodes.map((node) => ({ data: { id: node.id, label: node.label, type: node.type, risk_level: node.risk_level } })),
        ...edges.map((edge, index) => ({ data: { id: `edge-${index}`, source: edge.source, target: edge.target, label: edge.label } })),
      ],
      layout: { name: nodes.length > 12 ? 'circle' : 'cose', animate: false, padding: 34 },
      minZoom: 0.3,
      maxZoom: 2.5,
      style: [
        { selector: 'node', style: { label: 'data(label)', color: '#e8f0ee', 'font-size': '10px', 'font-family': 'IBM Plex Mono, monospace', 'text-wrap': 'wrap', 'text-max-width': '100px', 'text-valign': 'bottom', 'text-margin-y': 8, 'background-color': '#4ebdc0', width: '31px', height: '31px', 'border-width': '1px', 'border-color': '#9de3dd' } },
        { selector: 'node[type="user"]', style: { 'background-color': '#1b8391', shape: 'hexagon', width: '40px', height: '40px', 'border-color': '#63d6d0' } },
        { selector: 'node[type="user"][risk_level="HIGH"]', style: { 'border-width': '3px', 'border-color': '#ff817b', 'background-color': '#9a4848' } },
        { selector: 'node[type="user"][risk_level="CRITICAL"]', style: { 'border-width': '4px', 'border-color': '#ff9b9e', 'background-color': '#d84448' } },
        { selector: 'node[type="device"]', style: { 'background-color': '#b37d32', shape: 'round-rectangle', 'border-color': '#e8bd6c' } },
        { selector: 'node[type="ip"]', style: { 'background-color': '#bb5f50', shape: 'diamond', 'border-color': '#f09a85' } },
        { selector: 'node[type="email"], node[type="phone"]', style: { 'background-color': '#526c78', shape: 'ellipse', width: '25px', height: '25px', 'border-color': '#91a9b0' } },
        { selector: 'edge', style: { width: '1.5px', 'line-color': '#456068', 'target-arrow-color': '#66828a', 'target-arrow-shape': 'triangle', 'curve-style': 'bezier', label: 'data(label)', color: '#81969c', 'font-size': '8px', 'text-rotation': 'autorotate', 'text-background-color': '#111a1e', 'text-background-opacity': 0.9, 'text-background-padding': '2px' } },
        { selector: 'node:selected', style: { 'border-width': '3px', 'border-color': '#f3d278', 'overlay-color': '#f3d278', 'overlay-opacity': 0.12 } },
      ],
    })
    graphRef.current = graph
    graph.on('tap', 'node', (event) => {
      const selected = nodeMap.get(event.target.id())
      if (selected) onSelect?.(selected)
    })
    return () => { graph.destroy(); graphRef.current = null }
  }, [nodes, edges, nodeMap, onSelect])

  return <div className="graph-canvas-wrap"><div ref={container} className="graph-canvas" /><div className="graph-zoom-controls"><button className="icon-button" title="Zoom in" onClick={() => graphRef.current?.zoom({ level: graphRef.current.zoom() * 1.2, renderedPosition: { x: 240, y: 160 } })}>+</button><button className="icon-button" title="Zoom out" onClick={() => graphRef.current?.zoom({ level: graphRef.current.zoom() / 1.2, renderedPosition: { x: 240, y: 160 } })}>−</button><button className="icon-button" title="Fit graph" onClick={() => graphRef.current?.fit(undefined, 35)}><Layers3 size={15} /></button></div><div className="graph-legend"><span><i className="legend-user" />Users</span><span><i className="legend-device" />Devices</span><span><i className="legend-ip" />Networks</span><span><i className="legend-identifier" />Identifiers</span></div></div>
}

export function GraphPage() {
  const { userId: rawId } = useParams()
  const userId = Number(rawId)
  const [user, setUser] = useState<IdentityUser | null>(null)
  const [graph, setGraph] = useState<{ nodes: GraphNode[]; edges: { source: string; target: string; label: string }[] } | null>(null)
  const [selected, setSelected] = useState<GraphNode | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let alive = true
    Promise.all([dataApi.user(userId), dataApi.graph(userId)])
      .then(([userData, graphData]) => { if (alive) { setUser(userData); setGraph(graphData) } })
      .catch((requestError) => alive && setError(errorMessage(requestError)))
      .finally(() => alive && setLoading(false))
    return () => { alive = false }
  }, [userId])

  if (loading) return <LoadingState label="Building relationship graph from linked records..." />
  if (error || !user || !graph) return <RequestError message={error || 'Relationship graph unavailable.'} />
  return <>
    <PageHeading eyebrow="IDENTITY INTELLIGENCE / RELATIONSHIPS" title="Relationship graph" description={`${user.username} · ${graph.nodes.length} nodes · ${graph.edges.length} observed relationships`} action={<Link className="button button-secondary" to={`/users/${user.id}`}><Fingerprint size={15} /> Risk profile</Link>} />
    <ProfileTabs userId={user.id} current="graph" />
    {graph.nodes.length <= 3 ? <section className="panel"><EmptyState icon={<Network size={20} />} title="No connected entities found" detail="No shared device or network links have been recorded for this identity." /></section> : <section className="panel graph-panel"><div className="graph-panel-head"><div><SectionTitle title="Observed relationships" detail="Select a node to inspect its backend record." /></div><div className="graph-node-count"><Waypoints size={16} />{graph.nodes.length} NODES</div></div><div className="graph-layout"><RelationshipCanvas nodes={graph.nodes} edges={graph.edges} onSelect={setSelected} /><aside className="graph-details"><div className="eyebrow">SELECTED ENTITY</div>{selected ? <><div className={`graph-selected-icon selected-${selected.type}`}><GraphTypeIcon type={selected.type} /></div><h3>{selected.label}</h3><span className="graph-node-type">{selected.type.toUpperCase()}</span><p>{selected.details}</p>{selected.type === 'user' && <Link to={`/users/${selected.id.replace('user-', '')}`} className="text-link">Open identity <ArrowRight size={14} /></Link>}</> : <div className="graph-select-empty">Click a graph node to see its details.</div>}</aside></div></section>}
  </>
}

function GraphTypeIcon({ type }: { type: GraphNode['type'] }) {
  if (type === 'user') return <UserRound size={18} />
  if (type === 'device') return <Fingerprint size={18} />
  if (type === 'ip') return <Network size={18} />
  return <ShieldCheck size={18} />
}

export function InvestigationsPage() {
  const [investigations, setInvestigations] = useState<Investigation[]>([])
  const [filter, setFilter] = useState('all')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const navigate = useNavigate()

  async function load() {
    setLoading(true)
    try { setInvestigations(await dataApi.investigations()); setError('') } catch (requestError) { setError(errorMessage(requestError)) } finally { setLoading(false) }
  }

  useEffect(() => { void load() }, [])
  const filtered = investigations.filter((item) => filter === 'all' || item.status === filter)
  const filters = ['all', 'open', 'under_review', 'verification_required', 'resolved', 'false_positive']

  return <>
    <PageHeading eyebrow="CASE MANAGEMENT / INVESTIGATION CENTER" title="Investigation center" description="Review, document, and resolve identity-risk cases." action={<button className="button button-quiet" onClick={() => void load()}><RefreshCw size={15} /> Refresh queue</button>} />
    <div className="investigation-count-strip">{filters.slice(1).map((status) => <button key={status} onClick={() => setFilter(status)} className={filter === status ? 'selected' : ''}><span>{investigations.filter((item) => item.status === status).length}</span>{status.replaceAll('_', ' ')}</button>)}</div>
    <section className="panel table-panel"><SectionTitle title="Case queue" detail={`${filtered.length} matching investigations`} />{error && <RequestError message={error} retry={() => void load()} />}{loading ? <LoadingState /> : !filtered.length ? <EmptyState icon={<GitBranch size={20} />} title="No cases in this queue" detail="Open an investigation from an analyzed identity profile. Cases are persisted by the backend." action={<Link to="/identities" className="button button-secondary button-small">Browse identities</Link>} /> : <div className="table-scroll"><table><thead><tr><th>Case</th><th>Identity</th><th>Risk</th><th>Decision</th><th>Last updated</th><th>Status</th><th /></tr></thead><tbody>{filtered.map((item) => <tr key={item.id} onClick={() => navigate(`/investigations/${item.id}`)}><td className="case-id">CASE-{String(item.id).padStart(4, '0')}</td><td><span className="identity-cell"><span className="table-avatar"><UserRound size={15} /></span><span><strong>{item.username}</strong><small>{item.email}</small></span></span></td><td><RiskBadge level={item.risk_level} /></td><td className="muted">{item.decision}</td><td className="muted">{formatDate(item.updated_at)}</td><td><StatusBadge value={item.status} /></td><td><ChevronRight size={16} className="row-chevron" /></td></tr>)}</tbody></table></div>}</section>
  </>
}

export function InvestigationDetailPage() {
  const { investigationId: rawId } = useParams()
  const id = Number(rawId)
  const [record, setRecord] = useState<Investigation | null>(null)
  const [notes, setNotes] = useState('')
  const [status, setStatus] = useState('open')
  const [decision, setDecision] = useState('pending')
  const [error, setError] = useState('')
  const [saved, setSaved] = useState(false)
  const [loading, setLoading] = useState(true)

  async function load() {
    setLoading(true)
    try {
      const detail = await dataApi.investigation(id)
      setRecord(detail)
      setNotes(detail.notes ?? '')
      setStatus(detail.status)
      setDecision(detail.decision)
      setError('')
    } catch (requestError) { setError(errorMessage(requestError)) } finally { setLoading(false) }
  }

  useEffect(() => { void load() }, [id])

  async function save() {
    try {
      await dataApi.updateInvestigation(id, { status, decision, notes })
      setSaved(true)
      await load()
    } catch (requestError) { setError(errorMessage(requestError)) }
  }

  if (loading) return <LoadingState label="Loading case evidence..." />
  if (error || !record) return <RequestError message={error || 'Investigation not found.'} />
  const eventEntries = record.timeline ? [...record.timeline.behavior_events.map((event) => ({ label: event.event_type.replaceAll('_', ' '), time: event.timestamp })), ...record.timeline.identity_changes.map((change) => ({ label: `${change.field_changed} changed`, time: change.timestamp }))].sort((a, b) => new Date(b.time).valueOf() - new Date(a.time).valueOf()).slice(0, 8) : []
  return <>
    <div className="profile-breadcrumb"><Link to="/investigations">Investigations</Link><ChevronRight size={14} /><span>CASE-{String(record.id).padStart(4, '0')}</span></div>
    <PageHeading eyebrow="CASE MANAGEMENT / ACTIVE CASE" title={record.username} description={`${record.email} · opened ${formatDate(record.created_at)}`} action={<RiskBadge level={record.risk_level} />} />
    <div className="investigation-detail-grid">
      <div className="investigation-detail-main">
        <section className="panel case-risk-strip"><div><span className="eyebrow">CURRENT RISK</span><strong>{Number(record.risk_score).toFixed(1)}<small> / 100</small></strong></div><RiskBadge level={record.risk_level} /><Link className="text-link" to={`/users/${record.user_id}`}>Open identity profile <ArrowRight size={14} /></Link></section>
        <section className="panel"><SectionTitle title="Explainable indicators" detail="Persisted indicators from the latest assessment" />{record.indicators?.length ? <div className="indicator-cards">{record.indicators.map((item, index) => <IndicatorCard key={`${item.indicator_type}-${index}`} indicator={item} />)}</div> : <EmptyState title="No indicators saved" detail="Run analysis on the identity to generate evidence-linked indicators." />}</section>
        <section className="panel"><SectionTitle title="Recent case timeline" detail="Backend behavior events and identity changes" />{eventEntries.length ? <div className="case-timeline">{eventEntries.map((event, index) => <div className="case-timeline-row" key={`${event.label}-${index}`}><span className="mini-timeline-dot" /><strong>{event.label}</strong><time>{formatDate(event.time)}</time></div>)}</div> : <div className="compact-empty">No recorded behavior events or identity changes.</div>}</section>
        {record.graph && record.graph.nodes.length > 3 && <section className="panel"><SectionTitle title="Connected entities" detail={`${record.graph.nodes.length} observed graph nodes`} action={<Link to={`/users/${record.user_id}/graph`} className="text-link">Full graph <ArrowRight size={14} /></Link>} /><div className="case-graph-preview"><RelationshipCanvas nodes={record.graph.nodes} edges={record.graph.edges ?? []} /></div></section>}
      </div>
      <aside className="panel analyst-notes-panel"><SectionTitle title="Analyst decision" detail="Updates are saved to the case record" /><label className="field-label">CASE STATUS<select value={status} onChange={(event) => setStatus(event.target.value)}><option value="open">Open</option><option value="under_review">Under review</option><option value="verification_required">Verification required</option><option value="resolved">Resolved</option><option value="false_positive">False positive</option></select></label><label className="field-label">DECISION<select value={decision} onChange={(event) => setDecision(event.target.value)}><option value="pending">Pending</option><option value="confirmed">Confirmed</option><option value="cleared">Cleared</option><option value="false_positive">False positive</option></select></label><label className="field-label">ANALYST NOTES<textarea rows={7} value={notes} onChange={(event) => setNotes(event.target.value)} placeholder="Record observations and next steps..." /></label>{error && <RequestError message={error} />}{saved && <div className="save-confirmation"><Check size={15} /> Case updated</div>}<button className="button button-primary full-width" onClick={() => void save()}><Check size={15} /> Save case updates</button></aside>
    </div>
  </>
}

export function ScenariosPage() {
  const [scenarios, setScenarios] = useState<DemoScenario[]>([])
  const [selected, setSelected] = useState<DemoScenario | null>(null)
  const [result, setResult] = useState<any>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const [generating, setGenerating] = useState('')
  const navigate = useNavigate()

  useEffect(() => {
    let alive = true
    dataApi.scenarios().then((data) => alive && setScenarios(data)).catch((requestError) => alive && setError(errorMessage(requestError))).finally(() => alive && setLoading(false))
    return () => { alive = false }
  }, [])

  async function generate(scenario: DemoScenario) {
    setGenerating(scenario.id)
    setError('')
    setSelected(scenario)
    setResult(null)
    try {
      const generated = await dataApi.generateScenario(scenario.id)
      const analyses: AnalysisResult[] = []
      for (const userId of generated.user_ids as number[]) analyses.push(await dataApi.analyze(userId))
      setResult({ ...generated, analyses })
    } catch (requestError) { setError(errorMessage(requestError)) } finally { setGenerating('') }
  }

  if (loading) return <LoadingState label="Loading backend-supported scenarios..." />
  return <>
    <PageHeading eyebrow="DATA LAB / SCENARIO GENERATOR" title="Demo scenarios" description="Generate persistent synthetic records in the backend, then inspect their linked evidence." />
    <div className="notice notice-warning"><ShieldCheck size={18} /><div><strong>Real database writes</strong><span>Each run creates new scenario identities, event records, devices, and network links. Nothing is simulated in the browser.</span></div></div>
    {error && <RequestError message={error} />}
    <div className="scenario-grid">{scenarios.map((scenario, index) => <article className={`scenario-card scenario-card-${index % 4}`} key={scenario.id}><div className="scenario-card-top"><div className="scenario-icon"><ScenarioIcon scenario={scenario.id} /></div><span className="scenario-index">SCENARIO 0{index + 1}</span></div><h2>{scenario.label}</h2><p>{scenarioDescription(scenario.id)}</p><button className="button button-secondary" onClick={() => void generate(scenario)} disabled={Boolean(generating)}>{generating === scenario.id ? <><span className="spinner" /> Generating records</> : <>Generate scenario <ArrowRight size={15} /></>}</button></article>)}</div>
    {selected && result && <section className="panel scenario-result"><div className="scenario-result-head"><div><div className="eyebrow">BACKEND ANALYSIS COMPLETE</div><h2>{selected.label}</h2><p className="muted">{result.analyses.length} model-backed assessments saved from generated records.</p></div><span className="badge badge-low"><Check size={12} /> ANALYZED</span></div><div className="scenario-counts"><SummaryMetric label="Created identities" value={result.users} /><SummaryMetric label="Behavior events" value={result.behavior_events} /><SummaryMetric label="Device links" value={result.user_devices} /><SummaryMetric label="Network links" value={result.user_ips} /></div><div className="scenario-analysis-list">{result.analyses.map((analysis: AnalysisResult) => <button className="scenario-analysis-row" key={analysis.prediction_id} onClick={() => navigate(`/users/${analysis.user_id}`)}><span className="mono">USER-{String(analysis.user_id).padStart(5, '0')}</span><RiskBadge level={analysis.risk_level} /><strong>{analysis.risk_score.toFixed(1)}</strong><span>{analysis.decision}</span><ArrowRight size={14} /></button>)}</div></section>}
  </>
}

function ScenarioIcon({ scenario }: { scenario: string }) {
  if (scenario.includes('wifi') || scenario.includes('network')) return <Network size={18} />
  if (scenario.includes('farm') || scenario.includes('coordinated')) return <UsersRound size={18} />
  if (scenario.includes('device')) return <Fingerprint size={18} />
  if (scenario.includes('bot')) return <Activity size={18} />
  if (scenario.includes('rapid')) return <RefreshCw size={18} />
  return <UserRound size={18} />
}

function scenarioDescription(id: string) {
  const descriptions: Record<string, string> = {
    'normal-user': 'Mature verified account with ordinary device, network, and behavior history.',
    'shared-wifi': 'Established verified identities sharing a reputable network with normal activity.',
    'identity-farm': 'New identities connected through shared devices and networks with rapid changes.',
    'device-reuse': 'Multiple mature accounts linked to one device across distinct sessions.',
    'device-farm': 'A recent account cluster reuses a device and network while changing identity signals.',
    'bot-behaviour': 'High-frequency automated-style events attached to a single identity and device.',
    'rapid-identity-changes': 'One account with several phone, email, address, and device changes.',
    'coordinated-accounts': 'A registration burst sharing network and behavioral evidence.',
    'account-creation-burst': 'A short registration burst sharing device and network infrastructure.',
  }
  return descriptions[id] ?? 'Create a backend-stored identity pattern for analyst review.'
}