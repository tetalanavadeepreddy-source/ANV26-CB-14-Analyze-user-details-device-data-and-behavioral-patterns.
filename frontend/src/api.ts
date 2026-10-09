import axios, { AxiosError } from 'axios'

const tokenKey = 'identityguard.token'
const userKey = 'identityguard.user'

export const http = axios.create({
  baseURL: import.meta.env.VITE_API_URL ?? 'http://127.0.0.1:8000',
  timeout: 20000,
})

http.interceptors.request.use((config) => {
  const token = sessionStorage.getItem(tokenKey)
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

export interface IdentityUser {
  id: number
  username: string
  email: string
  role: string
  created_at: string
  identity_verification_status: string
  risk_score: number
  risk_level: string
  status: string
}

export interface FeatureVector {
  user_id: number
  account_age_hours: number
  account_age_days: number
  identity_change_count: number
  identity_changes_last_24h: number
  accounts_same_email: number
  email_exact_reuse_count: number
  email_domain_reuse_count: number
  accounts_same_phone: number
  phone_reuse_count: number
  accounts_same_address: number
  address_reuse_count: number
  verification_status: string
  verification_verified: number
  device_account_count: number
  device_usage_frequency: number
  device_reuse_score: number
  device_age_days: number
  devices_per_user: number
  device_change_frequency: number
  shared_device_count: number
  device_link_count: number
  ip_account_count: number
  ip_user_count: number
  shared_ip_count: number
  ip_link_count: number
  vpn_flag: boolean
  vpn_indicator: number
  proxy_flag: boolean
  proxy_indicator: number
  tor_flag: boolean
  tor_indicator: number
  ip_reputation: number
  ip_reputation_score: number
  ip_reputation_source: string
  location_change_frequency: number
  country_change_frequency: number
  average_session_duration: number
  session_duration: number
  device_change_count: number
  identity_changes_24h: number
  actions_per_minute: number
  requests_per_second: number
  average_action_interval: number
  action_interval_std: number
  repeated_action_ratio: number
  navigation_velocity: number
  login_velocity: number
  failed_login_count: number
  request_velocity: number
  account_creation_burst: number
  accounts_created_same_hour: number
  accounts_created_same_day: number
  login_burst_score: number
  time_between_identity_changes: number
  recent_identity_changes: number
  connected_user_count: number
  graph_degree: number
  cluster_size: number
  cluster_density: number
  suspicious_neighbor_count: number
  behavior_event_count: number
}

export interface RiskIndicator {
  id?: number
  indicator_type: string
  description: string
  severity: string
  feature_value: string
}

export interface BehaviorEvent {
  id: number
  user_id: number
  session_id: string
  event_type: string
  timestamp: string
  duration: number
  event_metadata: string
}

export interface IdentityChange {
  id: number
  user_id: number
  field_changed: string
  timestamp: string
}

export interface ObservationActivity {
  id: number
  activity_type: string
  timestamp: string
  details: string
}

export interface ObservationRecord {
  id: number
  user_id: number
  username: string
  risk_score: number
  risk_level: string
  reasons: string[]
  started_at: string
  updated_at: string
  status: string
  activities?: ObservationActivity[]
  devices?: { id: number; device_type: string; operating_system: string; browser: string }[]
  networks?: { country: string; region: string; isp: string }[]
}

export interface ObservationHistory {
  user_id: number
  is_observed: boolean
  active_observation: ObservationRecord | null
  history: ObservationRecord[]
}

export interface GraphNode {
  id: string
  label: string
  type: 'user' | 'device' | 'ip' | 'email' | 'phone' | 'address'
  details: string
  risk_level?: string
}

export interface GraphEdge {
  source: string
  target: string
  label: string
}

export interface Investigation {
  id: number
  user_id: number
  username: string
  email: string
  risk_score: number
  risk_level: string
  status: string
  decision: string
  notes: string
  analyst_id: number | null
  created_at: string
  updated_at: string
  indicators?: RiskIndicator[]
  timeline?: { behavior_events: BehaviorEvent[]; identity_changes: IdentityChange[] }
  graph?: { nodes: GraphNode[]; edges: GraphEdge[] }
}

export interface AnalysisResult {
  user_id: number
  session_id: string | null
  assessment_id: number
  prediction_id: number
  risk_score: number
  risk_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  decision: string
  confidence: number
  evidence_coverage: number
  ml_score: number
  ml_probability: number
  model_score: number
  model_status: string
  model_version: string
  rule_score: number
  graph_score: number
  behavior_score: number
  anomaly_score: number
  signal_scores: Record<string, number>
  weights: Record<string, number>
  top_reasons: { feature: string; signal: string; description: string; feature_value: number | string | boolean; signal_points: number; weighted_points: number }[]
  mitigating_reasons: string[]
  explanation_method: string
  features: FeatureVector
  indicators: RiskIndicator[]
}

export interface DashboardSummary {
  total_users: number
  active_sessions: number
  suspicious_devices: number
  suspicious_ips: number
  fraud_clusters: number
  critical_risk: number
  high_risk: number
  medium_risk: number
  low_risk: number
  open_investigations: number
  analyzed_users: number
}

export interface DemoScenario {
  id: string
  label: string
}

export interface ModelMetrics {
  model_status: string
  metrics: {
    model: string
    model_version: string
    feature_version: string
    dataset_version: string
    dataset: string
    dataset_size: number
    train_size: number
    test_size: number
    accuracy: number
    precision: number
    recall: number
    f1: number
    roc_auc: number
    confusion_matrix: number[][]
    trained_at: string
  } | null
  top_features: { feature: string; importance: number }[]
}

export const authApi = {
  async login(email: string, password: string) {
    const { data } = await http.post('/auth/login', { email, password })
    persistSession(data.token, data.user)
    return data.user as Pick<IdentityUser, 'id' | 'username' | 'email' | 'role'>
  },
  async register(username: string, email: string, password: string) {
    const { data } = await http.post('/auth/register', { username, email, password })
    persistSession(data.token, data.user)
    return data.user as Pick<IdentityUser, 'id' | 'username' | 'email' | 'role'>
  },
  async logout() {
    try {
      await http.post('/auth/logout').catch(() => undefined)
    } finally {
      sessionStorage.removeItem(tokenKey)
      sessionStorage.removeItem(userKey)
    }
  },
  isAuthenticated() {
    return Boolean(sessionStorage.getItem(tokenKey))
  },
  currentUser() {
    const raw = sessionStorage.getItem(userKey)
    return raw ? (JSON.parse(raw) as { id: number; username: string; email: string; role: string }) : null
  },
}

function persistSession(token: string, user: object) {
  sessionStorage.setItem(tokenKey, token)
  sessionStorage.setItem(userKey, JSON.stringify(user))
}

export const dataApi = {
  health: () => http.get('/health'),
  summary: async () => (await http.get<DashboardSummary>('/dashboard/summary')).data,
  riskDistribution: async () => (await http.get<{ level: string; count: number }[]>('/dashboard/risk-distribution')).data,
  recentAlerts: async () => (await http.get('/dashboard/recent-alerts')).data,
  topIndicators: async () => (await http.get('/dashboard/top-indicators')).data,
  modelMetrics: async () => (await http.get<ModelMetrics>('/models/metrics')).data,
  assessments: async () => (await http.get('/risk-assessments')).data,
  observations: async () => (await http.get<ObservationRecord[]>('/observations')).data,
  observationHistory: async (id: number) => (await http.get<ObservationHistory>(`/users/${id}/observation`)).data,
  users: async (search = '', riskLevel = '') => (await http.get<IdentityUser[]>('/users', { params: { search: search || undefined, risk_level: riskLevel || undefined } })).data,
  user: async (id: number) => (await http.get<IdentityUser>(`/users/${id}`)).data,
  risk: async (id: number) => (await http.get(`/users/${id}/risk`)).data,
  features: async (id: number) => (await http.get<FeatureVector>(`/users/${id}/features`)).data,
  events: async (id: number) => (await http.get<{ user_id: number; events: BehaviorEvent[] }>(`/users/${id}/events`)).data,
  timeline: async (id: number) => (await http.get<{ behavior_events: BehaviorEvent[]; identity_changes: IdentityChange[] }>(`/users/${id}/timeline`)).data,
  indicators: async (id: number) => (await http.get<RiskIndicator[]>(`/users/${id}/indicators`)).data,
  graph: async (id: number) => (await http.get<{ nodes: GraphNode[]; edges: GraphEdge[] }>(`/users/${id}/graph`)).data,
  analyze: async (id: number) => (await http.post<AnalysisResult>(`/users/${id}/analyze`)).data,
  analyzeRisk: async (payload: { user_id: number; device_id?: string; ip?: string; session_id?: string; events?: { event_type: string; duration?: number; timestamp?: string }[] }) => (await http.post<AnalysisResult>('/risk/analyze', payload)).data,
  predictionFeedback: async (id: number, action: 'CONFIRM_FRAUD' | 'FALSE_POSITIVE', note = '') =>
    (await http.post(`/risk/predictions/${id}/feedback`, { action, note })).data,
  investigations: async () => (await http.get<Investigation[]>('/investigations')).data,
  investigation: async (id: number) => (await http.get<Investigation>(`/investigations/${id}`)).data,
  openInvestigation: async (user_id: number) => (await http.post('/investigations', { user_id })).data,
  updateInvestigation: async (id: number, changes: Partial<Pick<Investigation, 'status' | 'decision' | 'notes'>>) =>
    (await http.patch(`/investigations/${id}`, changes)).data,
  requestVerification: async (id: number) => (await http.post(`/users/${id}/request-verification`)).data,
  scenarios: async () => (await http.get<DemoScenario[]>('/demo/scenarios')).data,
  generateScenario: async (scenario: string) => (await http.post(`/demo/scenarios/${scenario}`)).data,
}

export function errorMessage(error: unknown) {
  if (error instanceof AxiosError) {
    if (!error.response) return 'The backend could not be reached. Check that the API is running.'
    const detail = error.response.data?.detail
    if (Array.isArray(detail)) return detail.map((item) => item.msg).join(', ')
    if (typeof detail === 'string') return detail
    if (error.response.status === 401) return 'Your session has expired. Sign in again.'
    return `Request failed (${error.response.status}). Please try again.`
  }
  return 'Something went wrong. Please try again.'
}