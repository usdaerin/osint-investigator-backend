// server.js - Complete Backend for OSINT Investigator Pro
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const dotenv = require('dotenv');
const axios = require('axios');
const crypto = require('crypto');

dotenv.config();

const app = express();

// Security Middleware
app.use(helmet());
app.use(cors({
  origin: process.env.NODE_ENV === 'production' ? 'https://yourdomain.com' : true,
  credentials: true
}));

// Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message: 'Too many requests from this IP, please try again later.'
});
app.use('/api/', limiter);

// Body Parser
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Database Simulation (Replace with MongoDB/PostgreSQL in production)
let users = [
  {
    id: '1',
    username: 'analyst',
    email: 'analyst@osint.pro',
    password: '$2b$10$eIukV7zUvY7Z9X8Y7Z9X8Y7Z9X8Y7Z9X8Y7Z9X8Y7Z9X8Y7Z9X8Y7Z', // 'password'
    mfaEnabled: false,
    createdAt: new Date().toISOString()
  }
];

let cases = [
  {
    id: '1',
    title: 'John Doe Background Check',
    status: 'In Progress',
    tags: ['SOCMINT', 'Email'],
    lastUpdated: new Date().toISOString(),
    createdAt: new Date().toISOString(),
    userId: '1',
    notes: [],
    evidence: []
  }
];

let investigations = {};

// JWT Configuration
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production';
const JWT_EXPIRES_IN = '24h';

// Authentication Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Routes

// AUTH ROUTES
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // Validation
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    // Check if user exists
    const existingUser = users.find(u => u.email === email || u.username === username);
    if (existingUser) {
      return res.status(409).json({ error: 'User already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const newUser = {
      id: uuidv4(),
      username,
      email,
      password: hashedPassword,
      mfaEnabled: false,
      createdAt: new Date().toISOString()
    };

    users.push(newUser);

    // Generate JWT
    const token = jwt.sign(
      { userId: newUser.id, email: newUser.email },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );

    res.status(201).json({
      message: 'User registered successfully',
      token,
      user: {
        id: newUser.id,
        username: newUser.username,
        email: newUser.email,
        mfaEnabled: newUser.mfaEnabled
      }
    });

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }

    // Find user (by username or email)
    const user = users.find(u => u.username === username || u.email === username);
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Generate JWT
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        mfaEnabled: user.mfaEnabled
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// CASE MANAGEMENT ROUTES
app.get('/api/cases', authenticateToken, (req, res) => {
  try {
    const userCases = cases.filter(c => c.userId === req.user.userId);
    res.json(userCases);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch cases' });
  }
});

app.post('/api/cases', authenticateToken, (req, res) => {
  try {
    const { title, status = 'Open', tags = [] } = req.body;

    if (!title) {
      return res.status(400).json({ error: 'Title is required' });
    }

    const newCase = {
      id: uuidv4(),
      title,
      status,
      tags,
      lastUpdated: new Date().toISOString(),
      createdAt: new Date().toISOString(),
      userId: req.user.userId,
      notes: [],
      evidence: []
    };

    cases.push(newCase);
    res.status(201).json(newCase);

  } catch (error) {
    res.status(500).json({ error: 'Failed to create case' });
  }
});

app.get('/api/cases/:id', authenticateToken, (req, res) => {
  try {
    const caseItem = cases.find(c => c.id === req.params.id && c.userId === req.user.userId);
    if (!caseItem) {
      return res.status(404).json({ error: 'Case not found' });
    }
    res.json(caseItem);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch case' });
  }
});

app.put('/api/cases/:id', authenticateToken, (req, res) => {
  try {
    const caseIndex = cases.findIndex(c => c.id === req.params.id && c.userId === req.user.userId);
    if (caseIndex === -1) {
      return res.status(404).json({ error: 'Case not found' });
    }

    const { title, status, tags } = req.body;
    cases[caseIndex] = {
      ...cases[caseIndex],
      ...(title && { title }),
      ...(status && { status }),
      ...(tags && { tags }),
      lastUpdated: new Date().toISOString()
    };

    res.json(cases[caseIndex]);
  } catch (error) {
    res.status(500).json({ error: 'Failed to update case' });
  }
});

// OSINT MODULES
app.post('/api/osint/google-dork', authenticateToken, async (req, res) => {
  try {
    const { query } = req.body;
    if (!query) {
      return res.status(400).json({ error: 'Query is required' });
    }

    // In production, use SerpAPI or similar
    // For demo, return mock data
    const mockResults = Array.from({ length: 5 }, (_, i) => ({
      title: `Result ${i + 1} for "${query}"`,
      link: `https://example.com/result${i + 1}`,
      snippet: `This is a mock result showing how ${query} appears in search results. This demonstrates the dorking functionality.`,
      date: new Date(Date.now() - Math.random() * 10000000000).toISOString().split('T')[0]
    }));

    res.json({
      query,
      results: mockResults,
      totalResults: Math.floor(Math.random() * 1000),
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    res.status(500).json({ error: 'Google dork search failed' });
  }
});

app.post('/api/osint/whois', authenticateToken, async (req, res) => {
  try {
    const { domain } = req.body;
    if (!domain) {
      return res.status(400).json({ error: 'Domain is required' });
    }

    // Mock WHOIS data
    const mockWhois = {
      domainName: domain,
      registrar: 'GoDaddy.com, LLC',
      creationDate: '2023-01-15T10:30:00Z',
      expirationDate: '2025-01-15T10:30:00Z',
      updatedDate: '2024-03-20T08:15:00Z',
      nameServers: ['ns1.example.com', 'ns2.example.com'],
      status: 'clientTransferProhibited',
      registrant: {
        name: 'John Doe',
        organization: 'Example Inc.',
        country: 'US'
      },
      administrativeContact: {
        name: 'Jane Smith',
        email: 'admin@example.com'
      }
    };

    res.json(mockWhois);
  } catch (error) {
    res.status(500).json({ error: 'WHOIS lookup failed' });
  }
});

app.post('/api/osint/breach-check', authenticateToken, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }

    // Mock breach data
    const breaches = Math.random() > 0.5 ? [
      {
        name: 'Adobe 2013',
        date: '2013-10-04',
        description: 'Adobe suffered a major data breach affecting 153 million accounts.',
        dataClasses: ['Email addresses', 'Password hints', 'Encrypted passwords'],
        pwnCount: 1
      },
      {
        name: 'LinkedIn 2012',
        date: '2012-06-06',
        description: 'Over 164 million LinkedIn accounts were compromised.',
        dataClasses: ['Email addresses', 'Password hashes'],
        pwnCount: 1
      }
    ] : [];

    res.json({
      email,
      breached: breaches.length > 0,
      breaches,
      lastChecked: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({ error: 'Breach check failed' });
  }
});

app.post('/api/osint/socmint', authenticateToken, async (req, res) => {
  try {
    const { username, platform } = req.body;
    if (!username || !platform) {
      return res.status(400).json({ error: 'Username and platform are required' });
    }

    // Mock social media data
    const mockData = {
      username,
      platform,
      profileUrl: `https://${platform}.com/${username}`,
      followers: Math.floor(Math.random() * 10000),
      following: Math.floor(Math.random() * 5000),
      posts: Math.floor(Math.random() * 200),
      joinDate: '2020-05-15',
      verified: Math.random() > 0.8,
      bio: 'OSINT enthusiast and digital investigator',
      location: 'San Francisco, CA',
      website: 'https://example.com',
      recentActivity: Array.from({ length: 3 }, () => ({
        type: ['post', 'comment', 'like'][Math.floor(Math.random() * 3)],
        content: 'Interesting development in the world of cybersecurity...',
        timestamp: new Date(Date.now() - Math.random() * 86400000).toISOString(),
        engagement: {
          likes: Math.floor(Math.random() * 100),
          shares: Math.floor(Math.random() * 20)
        }
      }))
    };

    res.json(mockData);
  } catch (error) {
    res.status(500).json({ error: 'SOCMINT analysis failed' });
  }
});

// AI CHATBOT
app.post('/api/chat', authenticateToken, async (req, res) => {
  try {
    const { message, caseId } = req.body;
    if (!message) {
      return res.status(400).json({ error: 'Message is required' });
    }

    // Simple rule-based responses (replace with LLM API in production)
    const responses = [
      "I've analyzed your query. Consider running a Google dork search to find more information.",
      "Based on your investigation, I recommend checking breach databases for email exposure.",
      "You might want to analyze social media profiles to understand the target's network.",
      "Have you considered running a WHOIS lookup on the domain? This could reveal ownership details.",
      "I suggest creating a timeline of events to identify patterns in the target's activity."
    ];

    const randomResponse = responses[Math.floor(Math.random() * responses.length)];
    
    // Store conversation (in production, use database)
    if (!investigations[req.user.userId]) {
      investigations[req.user.userId] = {};
    }
    if (caseId && !investigations[req.user.userId][caseId]) {
      investigations[req.user.userId][caseId] = [];
    }
    
    const chatMessage = {
      id: uuidv4(),
      sender: 'user',
      message,
      timestamp: new Date().toISOString()
    };
    
    const botResponse = {
      id: uuidv4(),
      sender: 'bot',
      message: randomResponse,
      timestamp: new Date().toISOString()
    };

    if (caseId) {
      investigations[req.user.userId][caseId].push(chatMessage, botResponse);
    }

    res.json({
      response: randomResponse,
      suggestions: [
        "Run Google dork search",
        "Check breach databases",
        "Analyze social media"
      ],
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    res.status(500).json({ error: 'Chat processing failed' });
  }
});

// LINK ANALYSIS
app.post('/api/graph', authenticateToken, (req, res) => {
  try {
    const { entities } = req.body;
    if (!entities || !Array.isArray(entities)) {
      return res.status(400).json({ error: 'Entities array is required' });
    }

    // Create nodes and edges
    const nodes = entities.map(entity => ({
      data: {
        id: entity.id || crypto.createHash('md5').update(entity.value).digest('hex'),
        label: entity.value,
        type: entity.type
      }
    }));

    const edges = [];
    
    // Create connections between entities
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        // Connect if they might be related (simplified logic)
        if (Math.random() > 0.5) {
          edges.push({
            data: {
              source: nodes[i].data.id,
              target: nodes[j].data.id
            }
          });
        }
      }
    }

    res.json({ nodes, edges });
  } catch (error) {
    res.status(500).json({ error: 'Graph generation failed' });
  }
});

// HEALTH CHECK
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    version: '1.0.0'
  });
});

// Error Handling
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// 404 Handler
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`OSINT Investigator Pro backend running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});

module.exports = app;