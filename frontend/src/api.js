const API_ROOT = import.meta.env.VITE_API_URL || '/api'

async function request(path, options = {}) {
  const controller = new AbortController()
  const timeout = window.setTimeout(() => controller.abort(), 30000)
  try {
    const response = await fetch(`${API_ROOT}${path}`, { ...options, signal: controller.signal })
    const body = await response.json().catch(() => ({}))
    if (!response.ok) {
      throw new Error(body.detail || `Request failed (${response.status})`)
    }
    return body
  } catch (error) {
    if (error.name === 'AbortError') throw new Error('The backend request timed out')
    if (error instanceof TypeError) throw new Error('Backend unavailable. Start FastAPI on port 8000.')
    throw error
  } finally {
    window.clearTimeout(timeout)
  }
}

export const api = {
  health: () => request('/health'),
  alerts: (limit = 100) => request(`/alerts?limit=${limit}`),
  statistics: () => request('/statistics'),
  simulate: (payload) => request('/simulate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  }),
  analyzePcap: (file) => {
    const form = new FormData()
    form.append('file', file)
    return request('/analyze/pcap', { method: 'POST', body: form })
  },
}
