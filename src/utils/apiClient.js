const API_BASE_URL = process.env.REACT_APP_API_BASE_URL || 'http://localhost:8000/api';

const jsonHeaders = {
  Accept: 'application/json',
  'Content-Type': 'application/json',
};

const request = async (path, options = {}) => {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    credentials: 'include',
    ...options,
    headers: { ...jsonHeaders, ...(options.headers || {}) },
  });

  let payload;
  const text = await response.text();
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch (error) {
      payload = text;
    }
  }

  if (!response.ok) {
    const message = typeof payload === 'string' ? payload : payload?.detail || 'Request failed';
    throw new Error(message);
  }
  return payload;
};

const postJson = (path, body) => request(path, { method: 'POST', body: JSON.stringify(body) });

export const runPortScan = ({ target, mode, customPorts }) =>
  postJson('/port-scan', {
    target,
    mode,
    custom_ports: customPorts,
  });

export const runSqlScan = ({ url, parameter, payloadType }) =>
  postJson('/sqli-scan', {
    url,
    parameter,
    payload_type: payloadType,
  });

export const runXssScan = ({ url }) => postJson('/xss-scan', { url });

export const runHeaderScan = (url) => postJson('/header-analyzer', { url });

export const runDirectoryScan = ({ baseUrl, wordlist }) =>
  postJson('/directory-buster', { base_url: baseUrl, wordlist });

export const runOsintScan = (payload) => postJson('/osint', payload);

// History Management API
export const fetchHistory = (page = 1, perPage = 5) => 
  request(`/history?page=${page}&per_page=${perPage}`);

export const addHistoryEntry = (entry) => 
  postJson('/history', { entry });

export const deleteHistoryEntry = (entryId) => 
  request(`/history/${entryId}`, { method: 'DELETE' });

export const clearAllHistory = () => 
  request('/history', { method: 'DELETE' });

export const getUserStats = () => request('/user/stats');

// Legacy support
export const fetchHistoryLegacy = (seed = 5) => request(`/scan-history?seed=${seed}`);



export const runCredentialAudit = ({ samples }) => postJson('/credential-audit', { samples });

export const runWappalyzer = ({ domain }) => postJson('/wappalyzer', { domain });

export { API_BASE_URL };
