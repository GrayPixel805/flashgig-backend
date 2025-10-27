const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// File storage
const USERS_FILE = path.join(__dirname, 'users.json');
let users = [];

// Load users
try {
    if (fs.existsSync(USERS_FILE)) {
        const data = fs.readFileSync(USERS_FILE, 'utf8');
        if (data.trim()) {
            users = JSON.parse(data);
        }
    }
} catch (error) {
    console.log('Starting with empty users');
}

// Save users
function saveUsers() {
    try {
        fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
        return true;
    } catch (error) {
        console.error('Save error:', error);
        return false;
    }
}

const JWT_SECRET = process.env.JWT_SECRET || 'fallback-secret';

// Health check - CLEAR MARKER
app.get('/api/health', (req, res) => {
    res.json({
        success: true,
        message: '✅ FLASHGIG API WORKING - SERVER.JS',
        users: users.length,
        timestamp: new Date().toISOString(),
        version: 'FINAL-FIX-1.0'
    });
});

// Register
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, password, email } = req.body;

        if (!username || !password) {
            return res.status(400).json({
                success: false,
                message: 'Username and password required'
            });
        }

        if (users.find(u => u.username === username)) {
            return res.status(409).json({
                success: false,
                message: 'Username already exists'
            });
        }

        const hashedPassword = await bcrypt.hash(password, 12);
        
        const user = {
            username,
            email: email || '',
            password: hashedPassword,
            createdAt: new Date().toISOString()
        };
        
        users.push(user);
        saveUsers();

        const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '30d' });

        res.status(201).json({
            success: true,
            message: 'Registration successful',
            user: { username, email: user.email },
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

// Login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({
                success: false,
                message: 'Username and password required'
            });
        }

        const user = users.find(u => u.username === username);
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
                message: 'Invalid password'
            });
        }

        const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '30d' });

        res.json({
            success: true,
            message: 'Login successful',
            user: { username: user.username, email: user.email },
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

// Forgot password
app.post('/api/auth/forgot-password', async (req, res) => {
    try {
        const { username } = req.body;

        if (!username) {
            return res.status(400).json({
                success: false,
                message: 'Username required'
            });
        }

        const user = users.find(u => u.username === username);
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        const tempPassword = Math.random().toString(36).slice(-8);
        user.password = await bcrypt.hash(tempPassword, 12);
        
        saveUsers();

        res.json({
            success: true,
            message: `Temporary password: ${tempPassword}`,
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

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`🚀 SERVER.JS running on port ${PORT}`);
    console.log(`✅ Health: http://localhost:${PORT}/api/health`);
});
