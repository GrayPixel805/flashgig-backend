const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors({
    origin: ["http://localhost:3000", "http://127.0.0.1:3000", "https://your-flashgig-frontend.vercel.app"],
    credentials: true
}));
app.use(express.json());

// File-based database
const USERS_FILE = path.join(__dirname, 'users.json');

// Load users from file
function loadUsers() {
    try {
        if (fs.existsSync(USERS_FILE)) {
            const data = fs.readFileSync(USERS_FILE, 'utf8');
            const usersArray = JSON.parse(data);
            return new Map(usersArray);
        }
    } catch (error) {
        console.log('No existing users file, starting fresh...');
    }
    return new Map();
}

// Save users to file
function saveUsers(users) {
    try {
        const usersArray = Array.from(users.entries());
        fs.writeFileSync(USERS_FILE, JSON.stringify(usersArray, null, 2));
        console.log('Users saved to file successfully');
    } catch (error) {
        console.error('Error saving users:', error);
    }
}

// Initialize users
const users = loadUsers();
console.log(`Loaded ${users.size} existing users`);

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'flashgig-mvp-secret-key-2024';

// Input validation
function validateUsername(username) {
    if (!username || username.length < 3 || username.length > 20) {
        return 'Username must be between 3 and 20 characters';
    }
    if (!/^[a-zA-Z0-9_]+$/.test(username)) {
        return 'Username can only contain letters, numbers, and underscores';
    }
    return null;
}

function validatePassword(password) {
    if (!password || password.length < 8) {
        return 'Password must be at least 8 characters';
    }
    return null;
}

// Register endpoint
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, password } = req.body;

        console.log('Registration attempt:', { username });

        // Validate input
        const usernameError = validateUsername(username);
        if (usernameError) {
            return res.status(400).json({
                success: false,
                message: usernameError
            });
        }

        const passwordError = validatePassword(password);
        if (passwordError) {
            return res.status(400).json({
                success: false,
                message: passwordError
            });
        }

        // Check if user already exists
        if (users.has(username)) {
            return res.status(409).json({
                success: false,
                message: 'Username already exists. Would you like to log in instead?'
            });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 12);

        // Store user
        users.set(username, {
            username,
            password: hashedPassword,
            createdAt: new Date().toISOString(),
            lastLogin: null
        });

        // Save to file
        saveUsers(users);

        // Generate JWT token
        const token = jwt.sign(
            { 
                username,
                type: 'user'
            }, 
            JWT_SECRET, 
            { expiresIn: '30d' }
        );

        console.log('User registered successfully:', username);

        res.status(201).json({
            success: true,
            message: 'Registration successful',
            user: {
                username,
                createdAt: users.get(username).createdAt
            },
            token
        });

    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Login endpoint
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Validate input
        if (!username || !password) {
            return res.status(400).json({
                success: false,
                message: 'Username and password are required'
            });
        }

        // Find user
        const user = users.get(username);
        if (!user) {
            return res.status(401).json({
                success: false,
                message: 'Username not found. Would you like to sign up instead?'
            });
        }

        // Check password
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(401).json({
                success: false,
                message: 'Incorrect password. Please try again.'
            });
        }

        // Update last login
        user.lastLogin = new Date().toISOString();
        saveUsers(users); // Save the update

        // Generate token
        const token = jwt.sign(
            { 
                username,
                type: 'user'
            }, 
            JWT_SECRET, 
            { expiresIn: '30d' }
        );

        res.json({
            success: true,
            message: 'Login successful',
            user: {
                username,
                createdAt: user.createdAt,
                lastLogin: user.lastLogin
            },
            token
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Forgot password endpoint - OPTION 3 IMPLEMENTED
app.post('/api/auth/forgot-password', async (req, res) => {
    try {
        const { username } = req.body;

        if (!username) {
            return res.status(400).json({
                success: false,
                message: 'Username is required'
            });
        }

        // Check if user exists
        const user = users.get(username);
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'Username not found'
            });
        }

        // Generate temporary password (8 characters: letters and numbers)
        const tempPassword = Math.random().toString(36).slice(-8);
        user.password = await bcrypt.hash(tempPassword, 12);
        saveUsers(users);

        console.log(`Password reset for ${username}. Temp password: ${tempPassword}`);
        
        res.json({
            success: true,
            message: `Your temporary password is: ${tempPassword} - Use this to login and change your password immediately.`,
            tempPassword: tempPassword
        });

    } catch (error) {
        console.error('Forgot password error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Get user profile (protected)
app.get('/api/auth/profile', authenticateToken, (req, res) => {
    const user = users.get(req.user.username);
    if (!user) {
        return res.status(404).json({
            success: false,
            message: 'User not found'
        });
    }

    res.json({
        success: true,
        user: {
            username: user.username,
            createdAt: user.createdAt,
            lastLogin: user.lastLogin
        }
    });
});

// Middleware to verify JWT token
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({
            success: false,
            message: 'Access token required'
        });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({
                success: false,
                message: 'Invalid or expired token'
            });
        }
        req.user = user;
        next();
    });
}

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({
        success: true,
        message: 'FlashGig API is running',
        timestamp: new Date().toISOString(),
        usersCount: users.size
    });
});

// Get all users (for admin purposes - remove in production)
app.get('/api/admin/users', (req, res) => {
    const usersArray = Array.from(users.values()).map(user => ({
        username: user.username,
        createdAt: user.createdAt,
        lastLogin: user.lastLogin
    }));
    
    res.json({
        success: true,
        users: usersArray,
        total: users.size
    });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 FlashGig API server running on port ${PORT}`);
    console.log(`📍 Health check: http://localhost:${PORT}/api/health`);
    console.log(`👤 Register endpoint: http://localhost:${PORT}/api/auth/register`);
    console.log(`🔐 Login endpoint: http://localhost:${PORT}/api/auth/login`);
    console.log(`🔑 Forgot password: http://localhost:${PORT}/api/auth/forgot-password`);
    console.log(`💾 Data persistence: Enabled (users.json)`);
    console.log(`🔄 Password reset: Temporary passwords enabled`);
});
