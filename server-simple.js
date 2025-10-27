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
    origin: ["http://localhost:3000", "http://127.0.0.1:3000", "https://flashgig-backend.onrender.com"],
    credentials: true
}));
app.use(express.json());

// Simple in-memory storage with file backup
const USERS_FILE = path.join(__dirname, 'users.json');
let users = new Map();

// Load users from file
try {
    if (fs.existsSync(USERS_FILE)) {
        const data = fs.readFileSync(USERS_FILE, 'utf8');
        if (data.trim()) {
            const usersArray = JSON.parse(data);
            users = new Map(usersArray);
            console.log(`Loaded ${users.size} users from file`);
        }
    }
} catch (error) {
    console.log('Starting with fresh user data');
}

// Save users to file
function saveUsers() {
    try {
        const usersArray = Array.from(users.entries());
        fs.writeFileSync(USERS_FILE, JSON.stringify(usersArray, null, 2));
        return true;
    } catch (error) {
        console.error('Error saving users:', error);
        return false;
    }
}

const JWT_SECRET = process.env.JWT_SECRET || 'flashgig-secret-2024';

// Health check
app.get('/api/health', (req, res) => {
    res.json({
        success: true,
        message: 'FlashGig API is running',
        users: users.size,
        timestamp: new Date().toISOString()
    });
});

// Register endpoint
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, password, email } = req.body;

        if (!username || !password || !email) {
            return res.status(400).json({
                success: false,
                message: 'Username, password, and email are required'
            });
        }

        if (users.has(username)) {
            return res.status(409).json({
                success: false,
                message: 'Username already exists'
            });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 12);

        // Store user
        users.set(username, {
            username,
            email,
            password: hashedPassword,
            createdAt: new Date().toISOString(),
            lastLogin: null
        });

        saveUsers();

        // Generate token
        const token = jwt.sign({ username, email }, JWT_SECRET, { expiresIn: '30d' });

        res.status(201).json({
            success: true,
            message: 'Registration successful',
            user: { username, email, createdAt: users.get(username).createdAt },
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

        if (!username || !password) {
            return res.status(400).json({
                success: false,
                message: 'Username and password are required'
            });
        }

        const user = users.get(username);
        if (!user) {
            return res.status(401).json({
                success: false,
                message: 'Username not found'
            });
        }

        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(401).json({
                success: false,
                message: 'Incorrect password'
            });
        }

        // Update last login
        user.lastLogin = new Date().toISOString();
        saveUsers();

        const token = jwt.sign({ username: user.username, email: user.email }, JWT_SECRET, { expiresIn: '30d' });

        res.json({
            success: true,
            message: 'Login successful',
            user: {
                username: user.username,
                email: user.email,
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

// Forgot password endpoint
app.post('/api/auth/forgot-password', async (req, res) => {
    try {
        const { username } = req.body;

        if (!username) {
            return res.status(400).json({
                success: false,
                message: 'Username is required'
            });
        }

        const user = users.get(username);
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'Username not found'
            });
        }

        // Generate temporary password
        const tempPassword = Math.random().toString(36).slice(-8);
        user.password = await bcrypt.hash(tempPassword, 12);
        saveUsers();

        res.json({
            success: true,
            message: `Your temporary password is: ${tempPassword} - Use this to login immediately.`,
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

// Profile endpoint
app.get('/api/auth/profile', (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({
            success: false,
            message: 'Access token required'
        });
    }

    jwt.verify(token, JWT_SECRET, (err, userData) => {
        if (err) {
            return res.status(403).json({
                success: false,
                message: 'Invalid token'
            });
        }

        const user = users.get(userData.username);
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
                email: user.email,
                createdAt: user.createdAt,
                lastLogin: user.lastLogin
            }
        });
    });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 FlashGig Simple API running on port ${PORT}`);
    console.log(`📍 Health: http://localhost:${PORT}/api/health`);
});
