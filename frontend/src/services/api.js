const API_BASE = import.meta.env.VITE_API_BASE_URL || '';

class ApiService {
  async request(endpoint, options = {}) {
    const url = `${API_BASE}${endpoint}`;
    const defaultHeaders = {
      'Content-Type': 'application/json',
      Accept: 'application/json',
    };

    const config = {
      ...options,
      headers: {
        ...defaultHeaders,
        ...options.headers,
      },
    };

    try {
      const response = await fetch(url, config);
      const data = await response.json().catch(() => null);

      if (!response.ok) {
        const errorMsg = data?.detail || `API request failed with status ${response.status}`;
        throw new Error(errorMsg);
      }

      return data;
    } catch (err) {
      if (err.name === 'TypeError' && err.message.includes('fetch')) {
        throw new Error('Unable to connect to the LinkLens backend service. Please ensure the backend is running.');
      }
      throw err;
    }
  }

  async checkHealth() {
    return this.request('/api/health');
  }

  async analyzeUrl(url) {
    return this.request('/api/analyze', {
      method: 'POST',
      body: JSON.stringify({ url }),
    });
  }

  async getHistory({ page = 1, limit = 20, search = '', risk_level = '' } = {}) {
    const params = new URLSearchParams();
    if (page) params.append('page', page);
    if (limit) params.append('limit', limit);
    if (search) params.append('search', search);
    if (risk_level) params.append('risk_level', risk_level);

    return this.request(`/api/history?${params.toString()}`);
  }

  async getScanById(scanId) {
    return this.request(`/api/history/${encodeURIComponent(scanId)}`);
  }

  async deleteScan(scanId) {
    return this.request(`/api/history/${encodeURIComponent(scanId)}`, {
      method: 'DELETE',
    });
  }

  async getStats() {
    return this.request('/api/stats');
  }
}

export const api = new ApiService();
export default api;
