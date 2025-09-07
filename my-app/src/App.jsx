import React, { useState } from 'react';
import './App.css';

function App() {
  const [todos, setTodos] = useState([]);
  const [inputValue, setInputValue] = useState('');
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [user, setUser] = useState(null);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [isLogin, setIsLogin] = useState(true);
  const [loading, setLoading] = useState(false);
  const [token, setToken] = useState(null);
  // New states for edit functionality
  const [editingId, setEditingId] = useState(null);
  const [editValue, setEditValue] = useState('');

  // Fixed: Change from port 4000 to 3000 to match your backend
  const API_BASE = 'http://localhost:3000';

  const fetchTodos = async (authToken) => {
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/todos`, {
        headers: {
          'Authorization': `Bearer ${authToken}`,
          'Content-Type': 'application/json'
        },
      });
      if (!res.ok) {
        if (res.status === 401) {
          // Token expired, logout user
          handleLogout();
          return;
        }
        throw new Error('Failed to fetch todos');
      }
      const data = await res.json();
      setTodos(data);
    } catch (err) {
      console.error('Fetch todos error:', err);
      // Show user-friendly error
      if (err.message.includes('fetch')) {
        alert('Unable to connect to server. Please check if the backend is running.');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleAuth = async (e) => {
    e.preventDefault();
    setLoading(true);
    const endpoint = isLogin ? '/auth/signin' : '/auth/signup';

    try {
      const res = await fetch(`${API_BASE}${endpoint}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.error || 'Authentication failed');
      }

      setToken(data.token);
      setUser(data.user);
      setIsAuthenticated(true);
      setEmail('');
      setPassword('');

      // Fetch todos after successful authentication
      await fetchTodos(data.token);

    } catch (err) {
      console.error('Auth error:', err);

      // Show specific error messages
      if (err.message.includes('Invalid credentials')) {
        alert('Invalid email or password');
      } else if (err.message.includes('Email already in use')) {
        alert('An account with this email already exists');
      } else if (err.message.includes('fetch')) {
        alert('Unable to connect to server. Please check if the backend is running on http://localhost:3000');
      } else {
        alert(err.message || 'Authentication failed');
      }
    } finally {
      setLoading(false);
    }
  };

  const addTodo = async () => {
    if (!inputValue.trim()) return;

    try {
      const res = await fetch(`${API_BASE}/todos`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({ text: inputValue.trim() }),
      });

      if (!res.ok) {
        if (res.status === 401) {
          handleLogout();
          return;
        }
        const errorData = await res.json().catch(() => ({}));
        throw new Error(errorData.error || 'Error adding todo');
      }

      const newTodo = await res.json();
      setTodos((prev) => [newTodo, ...prev]);
      setInputValue('');

    } catch (err) {
      console.error('Add todo error:', err);
      alert(err.message || 'Failed to add todo');
    }
  };

  const toggleTodo = async (id, completed) => {
    try {
      const res = await fetch(`${API_BASE}/todos/${id}`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({ completed: !completed }),
      });

      if (!res.ok) {
        if (res.status === 401) {
          handleLogout();
          return;
        }
        throw new Error('Error updating todo');
      }

      const updatedTodo = await res.json();
      setTodos((prev) =>
        prev.map((todo) =>
          todo.id === id ? { ...todo, completed: !completed } : todo
        )
      );
    } catch (err) {
      console.error('Toggle todo error:', err);
      alert('Failed to update todo');
    }
  };

  // New edit functions
  const startEdit = (id, currentText) => {
    setEditingId(id);
    setEditValue(currentText);
  };

  const cancelEdit = () => {
    setEditingId(null);
    setEditValue('');
  };

  const saveEdit = async (id) => {
    if (!editValue.trim()) return;

    try {
      const res = await fetch(`${API_BASE}/todos/${id}`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({ text: editValue.trim() }),
      });

      if (!res.ok) {
        if (res.status === 401) {
          handleLogout();
          return;
        }
        const errorData = await res.json().catch(() => ({}));
        throw new Error(errorData.error || 'Error updating todo');
      }

      const updatedTodo = await res.json();
      setTodos((prev) =>
        prev.map((todo) =>
          todo.id === id ? { ...todo, text: editValue.trim() } : todo
        )
      );

      setEditingId(null);
      setEditValue('');

    } catch (err) {
      console.error('Edit todo error:', err);
      alert(err.message || 'Failed to update todo');
    }
  };

  const deleteTodo = async (id) => {
    try {
      const res = await fetch(`${API_BASE}/todos/${id}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
      });

      if (!res.ok) {
        if (res.status === 401) {
          handleLogout();
          return;
        }
        throw new Error('Error deleting todo');
      }

      setTodos((prev) => prev.filter((todo) => todo.id !== id));
    } catch (err) {
      console.error('Delete todo error:', err);
      alert('Failed to delete todo');
    }
  };

  const handleLogout = () => {
    setToken(null);
    setIsAuthenticated(false);
    setUser(null);
    setTodos([]);
    setEmail('');
    setPassword('');
    // Reset edit states
    setEditingId(null);
    setEditValue('');
  };

  if (!isAuthenticated) {
    return (
      <div className="login-container">
        <div className="login-card">
          <div className="text-center mb-8">
            <h1 className="text-4xl font-bold text-white mb-2">🚀 TodoSpace</h1>
            <p className="text-gray-300">
              Navigate your missions through the stellar void
            </p>
          </div>

          {loading && (
            <div className="text-center mb-4">
              <p className="text-gray-300">Loading...</p>
            </div>
          )}

          <form onSubmit={handleAuth} className="space-y-6 login-form">
            <input
              type="email"
              placeholder="Email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full px-4 py-3 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:border-blue-400"
              required
              disabled={loading}
            />
            <input
              type="password"
              placeholder="Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full px-4 py-3 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:border-blue-400"
              required
              disabled={loading}
            />
            <button
              type="submit"
              disabled={loading}
              className="bg-gradient-to-r from-blue-500 to-purple-600 text-white py-3 px-8 rounded-lg font-semibold hover:from-blue-600 hover:to-purple-700 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading
                ? '⏳ Loading...'
                : isLogin
                  ? '🚀 Launch'
                  : '⭐ Join the Quest'
              }
            </button>
          </form>
          <div className="text-center mt-6">
            <button
              onClick={() => setIsLogin(!isLogin)}
              className="text-gray-400 hover:text-white"
              disabled={loading}
            >
              {isLogin
                ? "Don't have an account? Sign up"
                : 'Already have an account? Sign in'}
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex items-center justify-center p-6">
      <div className="max-w-4xl mx-auto text-center w-full">
        <div className="text-center mb-8">
          <h1 className="text-5xl font-bold text-white mb-4">🚀 TodoSpace</h1>
          <p className="text-gray-300 text-lg mb-2">
            Welcome back, Commander {user?.name || user?.email}!
          </p>
          <div className="flex items-center justify-center gap-4">
            <span className="text-sm text-gray-400">
              {todos.filter((t) => t.completed).length} of {todos.length} missions
              completed
            </span>
            <button
              onClick={handleLogout}
              className="px-4 py-2 bg-red-500/20 border border-red-500/30 rounded-lg text-red-400 hover:bg-red-500/30"
            >
              🚀 Logout
            </button>
          </div>
        </div>

        <div className="bg-white/10 backdrop-blur-md rounded-lg p-6 mb-8 border border-white/20">
          <div className="flex gap-4">
            <input
              type="text"
              value={inputValue}
              onChange={(e) => setInputValue(e.target.value)}
              placeholder="Enter your next cosmic mission..."
              className="flex-1 px-4 py-3 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:border-blue-400"
              onKeyPress={(e) => e.key === 'Enter' && addTodo()}
              disabled={loading}
            />
            <button
              onClick={addTodo}
              disabled={!inputValue.trim() || loading}
              className="px-6 py-3 bg-gradient-to-r from-blue-500 to-purple-600 text-white rounded-lg font-semibold hover:from-blue-600 hover:to-purple-700 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              🚀 Launch
            </button>
          </div>
        </div>

        {loading ? (
          <p className="text-gray-400">Loading your missions...</p>
        ) : todos.length === 0 ? (
          <div className="bg-white/10 backdrop-blur-md rounded-lg p-12 text-center border border-white/20">
            <div className="text-6xl mb-4">⭐</div>
            <p className="text-gray-300 text-xl mb-2">No cosmic missions yet</p>
            <p className="text-gray-400">
              Add your first task to begin your stellar journey
            </p>
          </div>
        ) : (
          <div className="space-y-4">
            {todos.map((todo) => (
              <div
                key={todo.id}
                className={`bg-white/10 backdrop-blur-md rounded-lg p-4 border border-white/20 transition-all hover:bg-white/15 todo-item ${todo.completed ? 'opacity-75' : ''
                  }`}
              >
                <div className="flex items-center gap-4">
                  <button
                    onClick={() => toggleTodo(todo.id, todo.completed)}
                    className={`w-8 h-8 rounded-full border-2 flex items-center justify-center ${todo.completed
                      ? 'bg-green-500 border-green-500 text-white'
                      : 'border-white/30 hover:border-green-400'
                      }`}
                    disabled={editingId === todo.id}
                  >
                    {todo.completed && '✓'}
                  </button>
                  <div className="flex-1 text-left">
                    {editingId === todo.id ? (
                      <div className="flex gap-2 items-center">
                        <input
                          type="text"
                          value={editValue}
                          onChange={(e) => setEditValue(e.target.value)}
                          className="flex-1 px-3 py-2 bg-white/10 border border-white/20 rounded text-white focus:outline-none focus:border-blue-400"
                          onKeyPress={(e) => {
                            if (e.key === 'Enter') saveEdit(todo.id);
                            if (e.key === 'Escape') cancelEdit();
                          }}
                          autoFocus
                        />
                        <button
                          onClick={() => saveEdit(todo.id)}
                          className="w-8 h-8 flex items-center justify-center text-green-400 hover:text-green-300 hover:bg-green-500/20 rounded-lg"
                          disabled={!editValue.trim()}
                        >
                          ✓
                        </button>
                        <button
                          onClick={cancelEdit}
                          className="w-8 h-8 flex items-center justify-center text-gray-400 hover:text-gray-300 hover:bg-gray-500/20 rounded-lg"
                        >
                          ✕
                        </button>

                      </div>
                    ) : (
                      <p
                        className={
                          todo.completed
                            ? 'line-through text-gray-400'
                            : 'text-white'
                        }
                      >
                        {todo.text}
                      </p>
                    )}
                  </div>
                  {editingId !== todo.id && (
                    <div className="flex gap-2">
                      <button
                        onClick={() => startEdit(todo.id, todo.text)}
                        className="w-8 h-8 flex items-center justify-center text-blue-400 hover:text-blue-300 hover:bg-blue-500/20 rounded-lg"
                        disabled={todo.completed}
                        title="Edit mission"
                      >
                        ✏️
                      </button>
                      <button
                        onClick={() => deleteTodo(todo.id)}
                        className="w-8 h-8 flex items-center justify-center text-red-400 hover:text-red-300 hover:bg-red-500/20 rounded-lg"
                        title="Delete mission"
                      >
                        ✕
                      </button>
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}

        {todos.length > 0 && (
          <div className="bg-white/10 backdrop-blur-md rounded-lg p-6 mt-8 text-center border border-white/20">
            <p className="text-gray-300 mb-4">Mission Progress</p>
            <div className="w-full bg-white/20 rounded-full h-3 mb-2">
              <div
                className="bg-gradient-to-r from-blue-500 to-purple-600 h-3 rounded-full progress-bar"
                style={{
                  width: `${(todos.filter((t) => t.completed).length / todos.length) *
                    100
                    }%`,
                }}
              />
            </div>
            <p className="text-white font-medium">
              {Math.round(
                (todos.filter((t) => t.completed).length / todos.length) * 100
              )}
              % Complete
            </p>
          </div>
        )}
      </div>
    </div>
  );
}

export default App;