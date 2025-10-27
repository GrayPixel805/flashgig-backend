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

// Simple file-based storage
const USERS_FILE = path.join(__dirname, 'users.json');
let users = new Map();

// Load users
try {
    if (fs.existsSync(USERS_FILE)) {
        const data = fs.readFileSync(USERS_FILE, 'utf8');
        if (data.trim()) {
            const usersArray = JSON.parse(data);
            users = new Map(usersArray);
            console.log(`Loaded ${users.size} users`);
        }
    }
} catch (error) {
    console.log('Starting with fresh users');
}

// Save users
function saveUsers() {
    try {
        const usersArray = Array.from(users.entries());
        fs.writeFileSync(USERS_FILE, JSON.stringify(usersArray, null, 2));
        return true;
    } catch (error) {
        console.error('Save error:', error);
        return false;
    }
}

const JWT_SECRET = process.env.JWT_SECRET || 'flashgig-secret';

// Health check
app.get('/api/health', (req, res) => {
    res.json({
        success: true,
        message: 'FlashGig API is running',
        users: users.size,
        timestamp: new Date().toISOString()
    });
});

// Register
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, password, email } = req.body;

        if (!username || !password || !email) {
            return res.status(400).json({
                success: false,
                message: 'All fields are required'
            });
        }

        if (users.has(username)) {
            return res.status(409).json({
                success: false,
                message: 'Username exists'
            });
        }

        const hashedPassword = await bcrypt.hash(password, 12);
        
        // SIMPLE user object - no complex nested properties
        users.set(username, {
            username,
            email,
            password: hashedPassword,
            createdAt: new Date().toISOString(),
            lastLogin: null
            // No stats, no profile - keep it simple
        });

        saveUsers();

        const token = jwt.sign({ username, email }, JWT_SECRET, { expiresIn: '30d' });

        res.status(201).json({
            success: true,
            message: 'Registration successful',
            user: { username, email },
            token
        });

    } catch (error) {
        console.error('Register error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
});

// Login - SIMPLE VERSION
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({
                success: false,
                message: 'Username and password required'
            });
        }

        const user = users.get(username);
        if (!user) {
            return res.status(401).json({
                success: false,
                message: 'User not found'
            });
        }

        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(401).json({
                success: false,
                message: 'Wrong password'
            });
        }

        // SIMPLE update - no stats, no complex properties
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
            message: 'Server error'
        });
    }
});

// Forgot Password - SIMPLE VERSION
app.post('/api/auth/forgot-password', async (req, res) => {
    try {
        const { username } = req.body;

        if (!username) {
            return res.status(400).json({
                success: false,
                message: 'Username required'
            });
        }

        const user = users.get(username);
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        // Generate temp password
        const tempPassword = Math.random().toString(36).slice(-8);
        user.password = await bcrypt.hash(tempPassword, 12);
        
        // NO stats update - keep it simple
        saveUsers();

        res.json({
            success: true,
            message: `Temp password: ${tempPassword} - Use to login immediately`,
            tempPassword: tempPassword
        });

    } catch (error) {
        console.error('Forgot password error:', error);
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
});

// Profile
app.get('/api/auth/profile', (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({
            success: false,
            message: 'Token required'
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
    console.log(`🚀 FlashGig SIMPLE API running on port ${PORT}`);
});
