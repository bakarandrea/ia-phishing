import axios from 'axios';

export interface User {
  id: string;
  email: string;
}

export interface AuthResponse {
  token: string;
  user: User;
}

const API_URL = '/api/auth';

// Setup axios interceptor for JWT
axios.interceptors.request.use((config) => {
  const token = localStorage.getItem('ps_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

export const authService = {
  async login(email: string, password: string): Promise<User> {
    const { data } = await axios.post<AuthResponse>(`${API_URL}/login`, { email, password });
    localStorage.setItem('ps_token', data.token);
    return data.user;
  },

  async register(email: string, password: string): Promise<User> {
    const { data } = await axios.post<AuthResponse>(`${API_URL}/register`, { email, password });
    localStorage.setItem('ps_token', data.token);
    return data.user;
  },

  async me(): Promise<User | null> {
    const token = localStorage.getItem('ps_token');
    if (!token) return null;
    try {
      const { data } = await axios.get<{ user: User }>(`${API_URL}/me`);
      return data.user;
    } catch (err) {
      localStorage.removeItem('ps_token');
      return null;
    }
  },

  logout() {
    localStorage.removeItem('ps_token');
  }
};
