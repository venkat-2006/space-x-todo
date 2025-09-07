require("dotenv").config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/todoSpace';

// Validation helpers
const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;

function validateEmail(email) {
  if (!email || typeof email !== 'string') {
    return { isValid: false, error: 'Email is required' };
  }
  
  if (!emailRegex.test(email.trim())) {
    return { isValid: false, error: 'Please enter a valid email address' };
  }
  
  return { isValid: true };
}

function validatePassword(password) {
  if (!password || typeof password !== 'string') {
    return { isValid: false, error: 'Password is required' };
  }
  
  if (password.length < 8) {
    return { isValid: false, error: 'Password must be at least 8 characters long' };
  }
  
  if (!passwordRegex.test(password)) {
    return { 
      isValid: false, 
      error: 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character (@$!%*?&)' 
    };
  }
  
  return { isValid: true };
}

// MongoDB Connection
const connectDB = async () => {
  try {
    const conn = await mongoose.connect(MONGODB_URI);
    console.log(`MongoDB Connected: ${conn.connection.host}`);
  } catch (error) {
    console.error('Error connecting to MongoDB:', error.message);
    console.log('Falling back to in-memory storage');
    return false;
  }
  return true;
};

// MongoDB Models
const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    validate: {
      validator: function(email) {
        return emailRegex.test(email);
      },
      message: 'Please enter a valid email address'
    }
  },
  passwordHash: {
    type: String,
    required: true
  }
}, {
  timestamps: true
});

const todoSchema = new mongoose.Schema({
  text: {
    type: String,
    required: true,
    trim: true
  },
  completed: {
    type: Boolean,
    default: false
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  }
}, {
  timestamps: true
});

const User = mongoose.model('User', userSchema);
const Todo = mongoose.model('Todo', todoSchema);

// Connect to MongoDB
let isMongoConnected = false;
connectDB().then(connected => {
  isMongoConnected = connected;
});

// Fallback in-memory storage
const users = [];
const todosByUserId = new Map();
let nextUserId = 1;
let nextTodoId = 1;

app.use(cors({
  origin: ['http://localhost:5173', 'http://localhost:5174'],
  credentials: true
}));
app.use(express.json());

app.get('/', (req, res) => {
  res.json({ 
    message: 'TodoSpace API is running!', 
    database: isMongoConnected ? 'MongoDB' : 'In-Memory',
    endpoints: ['/auth/signup', '/auth/signin', '/todos'],
    validation: {
      email: 'Must be a valid email format',
      password: 'Minimum 8 characters with uppercase, lowercase, number, and special character'
    }
  });
});

// Helpers
function createToken(userId) {
  return jwt.sign({ sub: userId }, JWT_SECRET, { expiresIn: '7d' });
}

function auth(req, _res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return _res.status(401).json({ error: 'Missing token' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.sub;
    next();
  } catch {
    return _res.status(401).json({ error: 'Invalid token' });
  }
}

// Auth Routes with Validation
app.post('/auth/signup', async (req, res) => {
  const { email, password } = req.body || {};
  
  // Validate email
  const emailValidation = validateEmail(email);
  if (!emailValidation.isValid) {
    return res.status(400).json({ error: emailValidation.error });
  }
  
  // Validate password
  const passwordValidation = validatePassword(password);
  if (!passwordValidation.isValid) {
    return res.status(400).json({ error: passwordValidation.error });
  }

  try {
    const normalizedEmail = email.trim().toLowerCase();
    
    if (isMongoConnected) {
      // MongoDB implementation
      const existingUser = await User.findOne({ email: normalizedEmail });
      if (existingUser) {
        return res.status(409).json({ error: 'Email already in use' });
      }

      const passwordHash = await bcrypt.hash(password, 10);
      const user = new User({ email: normalizedEmail, passwordHash });
      await user.save();

      const token = createToken(user._id.toString());
      res.json({ 
        token, 
        user: { id: user._id.toString(), email: user.email },
        message: 'Account created successfully!'
      });
    } else {
      // Fallback to in-memory storage
      if (users.find(u => u.email === normalizedEmail)) {
        return res.status(409).json({ error: 'Email already in use' });
      }

      const passwordHash = await bcrypt.hash(password, 10);
      const user = { id: String(nextUserId++), email: normalizedEmail, passwordHash };
      users.push(user);
      todosByUserId.set(user.id, []);

      const token = createToken(user.id);
      res.json({ 
        token, 
        user: { id: user.id, email: user.email },
        message: 'Account created successfully!'
      });
    }
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/auth/signin', async (req, res) => {
  const { email, password } = req.body || {};
  
  // Validate email format
  const emailValidation = validateEmail(email);
  if (!emailValidation.isValid) {
    return res.status(400).json({ error: emailValidation.error });
  }
  
  if (!password) {
    return res.status(400).json({ error: 'Password is required' });
  }

  try {
    const normalizedEmail = email.trim().toLowerCase();
    
    if (isMongoConnected) {
      // MongoDB implementation
      const user = await User.findOne({ email: normalizedEmail });
      if (!user) {
        return res.status(401).json({ error: 'Invalid email or password' });
      }

      const ok = await bcrypt.compare(password, user.passwordHash);
      if (!ok) {
        return res.status(401).json({ error: 'Invalid email or password' });
      }

      const token = createToken(user._id.toString());
      res.json({ 
        token, 
        user: { id: user._id.toString(), email: user.email },
        message: 'Login successful!'
      });
    } else {
      // Fallback to in-memory storage
      const user = users.find(u => u.email === normalizedEmail);
      if (!user) {
        return res.status(401).json({ error: 'Invalid email or password' });
      }

      const ok = await bcrypt.compare(password, user.passwordHash);
      if (!ok) {
        return res.status(401).json({ error: 'Invalid email or password' });
      }

      const token = createToken(user.id);
      res.json({ 
        token, 
        user: { id: user.id, email: user.email },
        message: 'Login successful!'
      });
    }
  } catch (error) {
    console.error('Signin error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Validation endpoint for frontend
app.post('/auth/validate', (req, res) => {
  const { email, password } = req.body || {};
  
  const emailValidation = validateEmail(email);
  const passwordValidation = validatePassword(password);
  
  res.json({
    email: emailValidation,
    password: passwordValidation,
    isValid: emailValidation.isValid && passwordValidation.isValid
  });
});

app.get('/debug/db', async (req, res) => {
  try {
    if (!isMongoConnected) {
      return res.json({ 
        error: 'MongoDB not connected', 
        fallback: 'Using in-memory storage',
        solution: 'Check your MONGODB_URI in .env file'
      });
    }

    const dbName = mongoose.connection.name;
    let collections = [];
    let collectionNames = [];
    
    try {
      const db = mongoose.connection.db;
      collections = await db.listCollections().toArray();
      collectionNames = collections.map(c => c.name);
    } catch (listError) {
      console.log('No collections found or database is empty:', listError.message);
      collections = [];
      collectionNames = [];
    }
    
    let userCount = 0;
    let todoCount = 0;
    let sampleUsers = [];
    let sampleTodos = [];
    
    try {
      userCount = await User.countDocuments();
      todoCount = await Todo.countDocuments();
      
      if (userCount > 0) {
        sampleUsers = await User.find({}).limit(3).select('email createdAt');
      }
      if (todoCount > 0) {
        sampleTodos = await Todo.find({}).limit(3).select('text completed userId createdAt');
      }
    } catch (countError) {
      console.log('Error counting documents:', countError.message);
    }
    
    const response = {
      status: 'Connected to MongoDB',
      database: dbName,
      host: mongoose.connection.host,
      connectionString: MONGODB_URI.replace(/\/\/[^:]+:[^@]+@/, '//***:***@'),
      collections: collectionNames,
      collectionsCount: collectionNames.length,
      counts: {
        users: userCount,
        todos: todoCount
      },
      samples: {
        users: sampleUsers,
        todos: sampleTodos
      }
    };
    
    if (collectionNames.length === 0) {
      response.message = 'Database is empty. Collections will be created when you sign up your first user.';
      response.nextSteps = [
        'POST /auth/signup to create your first user',
        'POST /auth/signin to get a token',
        'POST /todos to create your first todo'
      ];
    }
    
    res.json(response);
    
  } catch (error) {
    console.error('Debug error:', error);
    res.status(500).json({ 
      error: error.message,
      suggestion: 'Your database exists but is empty. Try creating a user first.',
      mongodbConnected: isMongoConnected,
      database: mongoose.connection.name || 'unknown'
    });
  }
});

// Todo Routes (unchanged)
app.get('/todos', auth, async (req, res) => {
  try {
    if (isMongoConnected) {
      const todos = await Todo.find({ userId: req.userId }).sort({ createdAt: -1 });
      const formattedTodos = todos.map(todo => ({
        id: todo._id.toString(),
        text: todo.text,
        completed: todo.completed
      }));
      res.json(formattedTodos);
    } else {
      const todos = todosByUserId.get(req.userId) || [];
      res.json(todos);
    }
  } catch (error) {
    console.error('Get todos error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/todos', auth, async (req, res) => {
  const { text } = req.body || {};
  if (!text || !text.trim()) return res.status(400).json({ error: 'Text required' });

  try {
    if (isMongoConnected) {
      const todo = new Todo({
        text: text.trim(),
        userId: req.userId,
        completed: false
      });
      await todo.save();

      const formattedTodo = {
        id: todo._id.toString(),
        text: todo.text,
        completed: todo.completed
      };
      res.status(201).json(formattedTodo);
    } else {
      const todos = todosByUserId.get(req.userId) || [];
      const todo = { id: String(nextTodoId++), text: text.trim(), completed: false };
      todos.unshift(todo);
      todosByUserId.set(req.userId, todos);
      res.status(201).json(todo);
    }
  } catch (error) {
    console.error('Create todo error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.patch('/todos/:id', auth, async (req, res) => {
  const { id } = req.params;
  const { text, completed } = req.body || {};

  try {
    if (isMongoConnected) {
      const updateData = {};
      if (typeof text === 'string') updateData.text = text.trim();
      if (typeof completed === 'boolean') updateData.completed = completed;

      const todo = await Todo.findOneAndUpdate(
        { _id: id, userId: req.userId },
        updateData,
        { new: true }
      );

      if (!todo) return res.status(404).json({ error: 'Not found' });

      const formattedTodo = {
        id: todo._id.toString(),
        text: todo.text,
        completed: todo.completed
      };
      res.json(formattedTodo);
    } else {
      const todos = todosByUserId.get(req.userId) || [];
      const idx = todos.findIndex(t => t.id === id);
      if (idx === -1) return res.status(404).json({ error: 'Not found' });

      if (typeof text === 'string') todos[idx].text = text.trim();
      if (typeof completed === 'boolean') todos[idx].completed = completed;

      res.json(todos[idx]);
    }
  } catch (error) {
    console.error('Update todo error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.delete('/todos/:id', auth, async (req, res) => {
  const { id } = req.params;

  try {
    if (isMongoConnected) {
      const todo = await Todo.findOneAndDelete({ _id: id, userId: req.userId });
      if (!todo) return res.status(404).json({ error: 'Not found' });

      const formattedTodo = {
        id: todo._id.toString(),
        text: todo.text,
        completed: todo.completed
      };
      res.json(formattedTodo);
    } else {
      const todos = todosByUserId.get(req.userId) || [];
      const idx = todos.findIndex(t => t.id === id);
      if (idx === -1) return res.status(404).json({ error: 'Not found' });
      const [removed] = todos.splice(idx, 1);
      res.json(removed);
    }
  } catch (error) {
    console.error('Delete todo error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

app.listen(PORT, () => {
  console.log(`API listening on http://localhost:${PORT}`);
  console.log(`Database: ${isMongoConnected ? 'MongoDB' : 'In-Memory (fallback)'}`);
  console.log('Validation rules:');
  console.log('- Email: Valid email format required');
  console.log('- Password: Min 8 chars with uppercase, lowercase, number & special character');
});