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

// Simple file storage
const USERS_FILE = path.join(__dirname, 'users.json');
let users = new Map();

// Load users
try {
    if (fs.existsSync(USERS_FILE)) {
        const data = fs.readFileSync(USERS_FILE, 'utf8');
        if (data.trim()) {
            const parsed = JSON.parse(data);
            users = new Map(parsed);
        }
    }
} catch (error) {
    console.log('Starting fresh');
}

// Save users
function saveUsers() {
    try {
        const data = JSON.stringify(Array.from(users.entries()), null, 2);
        fs.writeFileSync(USERS_FILE, data);
        return true;
    } catch (error) {
        console.error('Save error:', error);
        return false;
    }
}

const JWT_SECRET = process.env.JWT_SECRET || 'flashgig-secret-key';

// Health check
app.get('/api/health', (req, res) => {
    res.json({
        success: true,
        message: 'FlashGig API is running',
        users: users.size,
        timestamp: new Date().toISOString(),
        version: 'ULTRA-SIMPLE-1.0'
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

        if (users.has(username)) {
            return res.status(409).json({
                success: false,
                message: 'Username already exists'
            });
        }

        const hashedPassword = await bcrypt.hash(password, 12);
        
        users.set(username, {
            username,
            email: email || '',
            password: hashedPassword,
            createdAt: new Date().toISOString()
            // NO lastLogin, NO stats, NO profile - keep it simple!
        });

        saveUsers();

        const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '30d' });

        res.status(201).json({
            success: true,
            message: 'Registration successful',
            user: { username },
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

// Login - NO COMPLEX PROPERTIES
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
                message: 'Invalid password'
            });
        }

        // Generate token - NO UPDATING USER PROPERTIES
        const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '30d' });

        res.json({
            success: true,
            message: 'Login successful',
            user: { username },
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

// Forgot password - SIMPLE
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
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 FlashGig ULTRA-SIMPLE API running on port ${PORT}`);
    console.log(`✅ No complex properties - no errors!`);
});
