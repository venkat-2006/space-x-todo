// Update BASE_URL to match your MongoDB backend
const BASE_URL = 'http://localhost:3000';

// In-memory token storage 
// In a real app, you'd use localStorage
let authToken = '';

export function getToken() {
  // Try localStorage first (for real applications), fallback to memory
  try {
    return localStorage.getItem('token') || authToken || '';
  } catch (error) {
    // localStorage not available , use memory storage
    return authToken || '';
  }
}

export function setToken(token) {
  if (token) {
    authToken = token; // Store in memory
    try {
      localStorage.setItem('token', token); // Try localStorage for real apps
    } catch (error) {
      // localStorage not available, memory storage already set above
      console.log('Using in-memory token storage');
    }
  }
}

export function clearToken() {
  authToken = ''; // Clear from memory
  try {
    localStorage.removeItem('token'); // Try localStorage for real apps
  } catch (error) {
    // localStorage not available, memory already cleared above
    console.log('Token cleared from memory storage');
  }
}

async function request(path, options = {}) {
  const headers = { 
    'Content-Type': 'application/json', 
    ...(options.headers || {}) 
  };
  
  const token = getToken();
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }
  
  try {
    const res = await fetch(`${BASE_URL}${path}`, { 
      ...options, 
      headers,
      credentials: 'include' // Include cookies if your backend uses them
    });
    
    const data = await res.json().catch(() => ({}));
    
    if (!res.ok) {
      // Handle specific error cases from your backend
      if (res.status === 401) {
        // Unauthorized - clear invalid token
        clearToken();
        throw new Error('Session expired. Please login again.');
      }
      throw new Error(data.error || `Request failed with status ${res.status}`);
    }
    
    return data;
  } catch (error) {
    // Handle network errors
    if (error.name === 'TypeError' && error.message.includes('fetch')) {
      throw new Error('Unable to connect to server. Please check if the backend is running on http://localhost:3000');
    }
    throw error;
  }
}

export const api = {
  // Authentication endpoints (matching your backend routes)
  signup(email, password) {
    return request('/auth/signup', { 
      method: 'POST', 
      body: JSON.stringify({ email, password }) 
    }).then(res => { 
      setToken(res.token); 
      return res; 
    });
  },

  signin(email, password) {
    return request('/auth/signin', { 
      method: 'POST', 
      body: JSON.stringify({ email, password }) 
    }).then(res => { 
      setToken(res.token); 
      return res; 
    });
  },

  // Todo endpoints (matching your backend routes)
  getTodos() { 
    return request('/todos'); 
  },

  addTodo(text) { 
    return request('/todos', { 
      method: 'POST', 
      body: JSON.stringify({ text }) 
    }); 
  },

  toggleTodo(id, completed) { 
    return request(`/todos/${id}`, { 
      method: 'PATCH', 
      body: JSON.stringify({ completed }) 
    }); 
  },

  updateTodo(id, text) { 
    return request(`/todos/${id}`, { 
      method: 'PATCH', 
      body: JSON.stringify({ text }) 
    }); 
  },

  deleteTodo(id) { 
    return request(`/todos/${id}`, { 
      method: 'DELETE' 
    }); 
  },

  // Additional helper methods
  logout() {
    clearToken();
    return Promise.resolve();
  },

  // Check if user is authenticated
  isAuthenticated() {
    return !!getToken();
  },

  // Get current user info (you might want to add a /me endpoint to your backend)
  getCurrentUser() {
    return request('/me'); // You'd need to add this endpoint to your backend
  },
};

// Export for easy debugging
export const debugApi = {
  getStoredToken: getToken,
  hasToken: () => !!getToken(),
  clearAll: clearToken,
};