import React, { createContext, useContext, useState, useEffect } from 'react';

const AuthContext = createContext(undefined);

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [isLoading, setIsLoading] = useState(false); // Changed to false - no persistent session to check 

  // Removed localStorage check since it doesn't work in Claude.ai
  // User starts as null and must login each session

  const login = async (email, password) => {
    setIsLoading(true);
    try {
      // Simulate API call with mock data for testing
      // Replace this with your actual API call
      const response = await fetch('/api/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email, password }),
      });
      
      if (!response.ok) {
        throw new Error('Login failed');
      }
      
      const userData = await response.json();
      const finalUser = {
        id: userData.id,
        email: userData.email,
        name: userData.name || userData.email.split('@')[0],
      };
      
      setUser(finalUser);
      // Removed localStorage.setItem since it doesn't work in Claude.ai
    } catch (error) {
      // For demo purposes, you can add a fallback mock login
      console.error('Login error:', error);
      alert('Login failed. Please try again.');
      throw error; // Re-throw to let the calling component handle it
    } finally {
      setIsLoading(false);
    }
  };

  const signup = async (email, password, name) => {
    setIsLoading(true);
    try {
      const response = await fetch('/api/signup', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email, password, name }),
      });
      
      if (!response.ok) {
        throw new Error('Signup failed');
      }
      
      const userData = await response.json();
      const finalUser = {
        id: userData.id,
        email: userData.email,
        name: userData.name || name || userData.email.split('@')[0],
      };
      
      setUser(finalUser);
      // Removed localStorage.setItem since it doesn't work in Claude.ai
    } catch (error) {
      console.error('Signup error:', error);
      alert('Signup failed. Please try again.');
      throw error; // Re-throw to let the calling component handle it
    } finally {
      setIsLoading(false);
    }
  };

  const logout = () => {
    setUser(null);
    // Removed localStorage.removeItem since it doesn't work in Claude.ai
  };

  const value = {
    user,
    isLoading,
    login,
    signup,
    logout,
    isAuthenticated: !!user,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};