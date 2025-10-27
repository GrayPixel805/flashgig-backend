const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

const app = express();

app.use(cors());
app.use(express.json());

const USERS_FILE = path.join(__dirname, 'users.json');
let users = [];

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

function saveUsers() {
    try {
        fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
        console.log('Users saved:', users.length);
        return true;
    } catch (error) {
        console.error('Save error:', error);
        return false;
    }
}

const JWT_SECRET = process.env.JWT_SECRET || 'fallback-secret';

app.get('/api/health', (req, res) => {
    res.json({
        success: true,
        message: 'API WORKING',
        users: users.length,
        version: 'DEBUG-1.0'
    });
});

app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, password, email } = req.body;

        if (!username || !password) {
            return res.status(400).json({ success: false, message: 'Need username/password' });
        }

        if (users.find(u => u.username === username)) {
            return res.status(409).json({ success: false, message: 'User exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 12);
        
        users.push({
            username,
            email: email || '',
            password: hashedPassword,
            createdAt: new Date().toISOString()
        });
        
        saveUsers();

        const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '30d' });

        res.json({
            success: true,
            message: 'Registered',
            user: { username },
            token
        });

    } catch (error) {
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ success: false, message: 'Need both' });
        }

        const user = users.find(u => u.username === username);
        if (!user) {
            return res.status(401).json({ success: false, message: 'User not found' });
        }

        console.log('Login attempt:', username, 'Password length:', password.length);
        console.log('Stored hash:', user.password.substring(0, 20) + '...');

        const valid = await bcrypt.compare(password, user.password);
        console.log('Password valid:', valid);

        if (!valid) {
            return res.status(401).json({ success: false, message: 'Wrong password' });
        }

        const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '30d' });

        res.json({
            success: true,
            message: 'Logged in!',
            user: { username },
            token
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// FIXED: Forgot password with proper debugging
app.post('/api/auth/forgot-password', async (req, res) => {
    try {
        const { username } = req.body;

        if (!username) {
            return res.status(400).json({ success: false, message: 'Need username' });
        }

        const user = users.find(u => u.username === username);
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        const tempPassword = Math.random().toString(36).slice(-8);
        console.log('Generated temp password for', username, ':', tempPassword);
        
        // Hash and save the temp password
        user.password = await bcrypt.hash(tempPassword, 12);
        console.log('New password hash:', user.password.substring(0, 20) + '...');
        
        const saved = saveUsers();
        console.log('Save successful:', saved);

        res.json({
            success: true,
            message: `Temp: ${tempPassword}`,
            tempPassword: tempPassword
        });

    } catch (error) {
        console.error('Forgot password error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log('🚀 DEBUG Server on port', PORT);
});
