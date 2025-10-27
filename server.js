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

// Simple storage
const USERS_FILE = path.join(__dirname, 'users.json');
let users = new Map();

// Load users - SUPER SIMPLE
try {
    if (fs.existsSync(USERS_FILE)) {
        const data = fs.readFileSync(USERS_FILE, 'utf8');
        if (data) {
            users = new Map(JSON.parse(data));
        }
    }
} catch (e) {
    console.log('Fresh start');
}

function saveUsers() {
    try {
        fs.writeFileSync(USERS_FILE, JSON.stringify(Array.from(users.entries())));
        return true;
    } catch (e) {
        return false;
    }
}

const JWT_SECRET = process.env.JWT_SECRET || 'test-secret';

// Health - SIMPLE
app.get('/api/health', (req, res) => {
    res.json({ 
        success: true, 
        message: 'API WORKING', 
        users: users.size,
        version: 'SIMPLE-1.0'
    });
});

// Register - SUPER SIMPLE
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, password, email } = req.body;

        if (!username || !password) {
            return res.status(400).json({ success: false, message: 'Need username/password' });
        }

        if (users.has(username)) {
            return res.status(409).json({ success: false, message: 'User exists' });
        }

        const hashed = await bcrypt.hash(password, 12);
        users.set(username, {
            username,
            email: email || '',
            password: hashed,
            createdAt: new Date().toISOString()
        });

        saveUsers();

        const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '30d' });

        res.json({
            success: true,
            message: 'Registered!',
            user: { username },
            token
        });

    } catch (error) {
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Login - SUPER SIMPLE
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ success: false, message: 'Need both' });
        }

        const user = users.get(username);
        if (!user) {
            return res.status(401).json({ success: false, message: 'User not found' });
        }

        const valid = await bcrypt.compare(password, user.password);
        if (!valid) {
            return res.status(401).json({ success: false, message: 'Wrong password' });
        }

        // NO lastActive, NO stats - just login
        const token = jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: '30d' });

        res.json({
            success: true,
            message: 'Logged in!',
            user: { username: user.username },
            token
        });

    } catch (error) {
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Forgot Password - SUPER SIMPLE
app.post('/api/auth/forgot-password', async (req, res) => {
    try {
        const { username } = req.body;

        if (!username) {
            return res.status(400).json({ success: false, message: 'Need username' });
        }

        const user = users.get(username);
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        const tempPassword = Math.random().toString(36).slice(-8);
        user.password = await bcrypt.hash(tempPassword, 12);
        
        saveUsers();

        res.json({
            success: true,
            message: `Use this password: ${tempPassword}`,
            tempPassword: tempPassword
        });

    } catch (error) {
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`🚀 SERVER RUNNING ON PORT ${PORT}`);
});
