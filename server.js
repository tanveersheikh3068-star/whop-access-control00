const express = require('express');
const session = require('express-session');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');
const path = require('path');
const dotenv = require('dotenv');
const { getDb, initDatabase } = require('./database');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 } // 24 hours
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use('/api/', limiter);

// Email setup
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Initialize database
let db;
initDatabase().then(database => {
  db = database;
  console.log('📦 Database ready');
});

// Auth middleware
const requireAdmin = (req, res, next) => {
  if (!req.session.admin) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
};

// ============= API ROUTES =============

// Admin login
app.post('/api/admin/login', async (req, res) => {
  const { password } = req.body;
  
  if (password === process.env.ADMIN_PASSWORD) {
    req.session.admin = true;
    res.json({ success: true });
  } else {
    res.status(401).json({ error: 'Invalid password' });
  }
});

// Admin logout
app.post('/api/admin/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

// Generate new student token
app.post('/api/admin/generate-token', requireAdmin, async (req, res) => {
  const { email } = req.body;
  
  if (!email || !email.includes('@')) {
    return res.status(400).json({ error: 'Valid email required' });
  }
  
  try {
    // Check if student already exists
    const existing = await db.get(
      'SELECT * FROM students WHERE email = ?',
      email
    );
    
    if (existing && existing.is_active) {
      return res.status(400).json({ 
        error: 'Student already has active token',
        token: existing.token 
      });
    }
    
    // Generate new token
    const token = uuidv4();
    const expiryDate = new Date();
    expiryDate.setDate(expiryDate.getDate() + parseInt(process.env.TOKEN_EXPIRY_DAYS || 30));
    
    if (existing) {
      // Reactivate existing
      await db.run(
        'UPDATE students SET token = ?, expires_at = ?, is_active = 1 WHERE email = ?',
        [token, expiryDate.toISOString(), email]
      );
    } else {
      // Create new
      await db.run(
        'INSERT INTO students (email, token, expires_at) VALUES (?, ?, ?)',
        [email, token, expiryDate.toISOString()]
      );
    }
    
    res.json({ 
      success: true, 
      token,
      expires: expiryDate
    });
    
  } catch (error) {
    console.error('Token generation error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get all active students
app.get('/api/admin/students', requireAdmin, async (req, res) => {
  const students = await db.all(`
    SELECT * FROM students 
    ORDER BY created_at DESC
  `);
  res.json(students);
});

// Revoke student access
app.post('/api/admin/revoke/:id', requireAdmin, async (req, res) => {
  const { id } = req.params;
  
  await db.run(
    'UPDATE students SET is_active = 0 WHERE id = ?',
    id
  );
  
  res.json({ success: true });
});

// Get login history
app.get('/api/admin/login-history', requireAdmin, async (req, res) => {
  const history = await db.all(`
    SELECT * FROM login_history 
    ORDER BY login_time DESC 
    LIMIT 100
  `);
  res.json(history);
});

// ============= STUDENT ROUTES =============

// Student login verification
app.post('/api/student/verify', async (req, res) => {
  const { email, token } = req.body;
  const ip = req.ip || req.connection.remoteAddress;
  const userAgent = req.headers['user-agent'];
  
  // Find student
  const student = await db.get(
    'SELECT * FROM students WHERE email = ? AND token = ? AND is_active = 1',
    [email, token]
  );
  
  if (!student) {
    // Log failed attempt
    await db.run(
      'INSERT INTO login_history (email, ip, user_agent, success) VALUES (?, ?, ?, ?)',
      [email, ip, userAgent, false]
    );
    
    return res.status(401).json({ error: 'Invalid credentials or access revoked' });
  }
  
  // Check expiry
  const now = new Date();
  const expiry = new Date(student.expires_at);
  
  if (now > expiry) {
    await db.run(
      'UPDATE students SET is_active = 0 WHERE id = ?',
      student.id
    );
    
    return res.status(401).json({ error: 'Token expired' });
  }
  
  // Update last login
  await db.run(
    'UPDATE students SET last_login = ?, last_ip = ? WHERE id = ?',
    [now.toISOString(), ip, student.id]
  );
  
  // Log successful login
  await db.run(
    'INSERT INTO login_history (student_id, email, ip, user_agent, success) VALUES (?, ?, ?, ?, ?)',
    [student.id, email, ip, userAgent, true]
  );
  
  // Send email alert to admin
  try {
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: process.env.ADMIN_EMAIL,
      subject: `🔐 Student Login: ${email}`,
      html: `
        <h2>New Student Login</h2>
        <p><strong>Email:</strong> ${email}</p>
        <p><strong>IP Address:</strong> ${ip}</p>
        <p><strong>Time:</strong> ${now.toLocaleString()}</p>
        <p><strong>User Agent:</strong> ${userAgent}</p>
      `
    });
  } catch (emailError) {
    console.error('Email alert failed:', emailError);
    // Don't fail the login if email fails
  }
  
  // Redirect to Whop course
  res.json({ 
    success: true,
    redirect: process.env.COURSE_LINK,
    message: 'Login successful! Redirecting to course...'
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
