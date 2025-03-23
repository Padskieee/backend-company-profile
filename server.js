const express = require('express');
const path = require('path');
const bcryptjs = require('bcryptjs');
const session = require('express-session');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Session configuration
app.use(session({
  secret: 'your_secure_secret_key',
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: false,
    maxAge: 3600000 // Session expires in 1 hour
  }
}));

// Set view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// In-memory user database for demonstration
const users = [
  {
    id: 1,
    email: 'admin@example.com',
    // Default password is "password123"
    password: '$2a$10$CwTycUXWue0Thq9StjUM0uQxTmrjFPgCwh8qP.iEOH0aF9XQTQzWK'
  }
];

// Authentication middleware
const requireAuth = (req, res, next) => {
  if (req.session.userId) {
    return next();
  }
  res.redirect('/login');
};

// Routes

// Home route
app.get('/', (req, res) => {
  res.render('index', { user: req.session.userId ? users.find(u => u.id === req.session.userId) : null });
});

// Login page
app.get('/login', (req, res) => {
  if (req.session.userId) {
    return res.redirect('/dashboard');
  }
  res.render('login', { error: null });
});

// Login form submission
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  
  // Find user by email
  const user = users.find(u => u.email === email);
  
  if (!user) {
    return res.render('login', { error: 'Invalid email or password' });
  }
  
  // Compare password with stored hash
  const match = await bcryptjs.compare(password, user.password);
  
  if (!match) {
    return res.render('login', { error: 'Invalid email or password' });
  }
  
  // Set user session
  req.session.userId = user.id;
  res.redirect('/dashboard');
});

// Register page
app.get('/register', (req, res) => {
  if (req.session.userId) {
    return res.redirect('/dashboard');
  }
  res.render('register', { error: null });
});

// Register form submission
app.post('/register', async (req, res) => {
  const { email, password, confirmPassword } = req.body;
  
  // Basic validation
  if (!email || !password) {
    return res.render('register', { error: 'Email and password are required' });
  }
  
  if (password !== confirmPassword) {
    return res.render('register', { error: 'Passwords do not match' });
  }
  
  // Check if user already exists
  if (users.some(u => u.email === email)) {
    return res.render('register', { error: 'Email already registered' });
  }
  
  try {
    // Hash password
    const hashedPassword = await bcryptjs.hash(password, 10);
    
    // Create new user
    const newUser = {
      id: users.length + 1,
      email,
      password: hashedPassword
    };
    
    users.push(newUser);
    
    // Set user session
    req.session.userId = newUser.id;
    res.redirect('/dashboard');
  } catch (error) {
    console.error('Error hashing password:', error);
    res.render('register', { error: 'An error occurred. Please try again.' });
  }
});

// Protected dashboard route
app.get('/dashboard', requireAuth, (req, res) => {
  const user = users.find(u => u.id === req.session.userId);
  if (!user) {
    req.session.destroy();
    return res.redirect('/login');
  }
  res.render('dashboard', { user });
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login');
});

// Health check endpoint for Railway
app.get('/health', (req, res) => {
  res.status(200).send('OK');
});

// Catch-all route for any non-existing paths
app.get('*', (req, res) => {
  res.redirect('/');
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).render('error', { 
    error: process.env.NODE_ENV === 'production' ? 'An error occurred' : err.message 
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});