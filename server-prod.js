const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

const app = express();

// Enhanced CORS for global access
app.use(cors({
    origin: [
        "http://localhost:3000",
        "http://127.0.0.1:3000", 
        "https://your-flashgig.vercel.app",
        "https://*.vercel.app",
        "https://*.netlify.app"
    ],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

// Security middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Rate limiting (basic)
const requestCounts = new Map();
app.use((req, res, next) => {
    const ip = req.ip || req.connection.remoteAddress;
    const now = Date.now();
    const windowStart = now - 60000; // 1 minute window
    
    if (!requestCounts.has(ip)) {
        requestCounts.set(ip, []);
    }
    
    const requests = requestCounts.get(ip).filter(time => time > windowStart);
    requests.push(now);
    requestCounts.set(ip, requests);
    
    if (requests.length > 60) { // 60 requests per minute
        return res.status(429).json({
            success: false,
            message: 'Too many requests. Please try again later.'
        });
    }
    
    next();
});

// File-based database (will upgrade to Supabase)
const USERS_FILE = path.join(__dirname, 'users.json');
const SCOPES_FILE = path.join(__dirname, 'scopes.json');

// Enhanced data loading with backups
function loadData(file) {
    try {
        if (fs.existsSync(file)) {
            const data = fs.readFileSync(file, 'utf8');
            return new Map(JSON.parse(data));
        }
    } catch (error) {
        console.log(`No existing ${file}, starting fresh...`);
        // Create backup of corrupted file
        if (fs.existsSync(file)) {
            const backupName = `${file}.corrupted.${Date.now()}`;
            fs.renameSync(file, backupName);
            console.log(`Created backup of corrupted file: ${backupName}`);
        }
    }
    return new Map();
}

function saveData(data, file) {
    try {
        const dataArray = Array.from(data.entries());
        fs.writeFileSync(file, JSON.stringify(dataArray, null, 2));
        console.log(`Data saved to ${file} successfully`);
    } catch (error) {
        console.error(`Error saving to ${file}:`, error);
    }
}

// Initialize data stores
const users = loadData(USERS_FILE);
const scopes = loadData(SCOPES_FILE);
console.log(`Loaded ${users.size} users and ${scopes.size} scopes`);

// JWT Secret from environment
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
    console.error('❌ JWT_SECRET environment variable is required!');
    process.exit(1);
}

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

function validateEmail(email) {
    if (!email) return 'Email is required';
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return 'Please enter a valid email address';
    }
    return null;
}

// Enhanced user registration with email
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, password, email } = req.body;

        console.log('Registration attempt:', { username, email });

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

        const emailError = validateEmail(email);
        if (emailError) {
            return res.status(400).json({
                success: false,
                message: emailError
            });
        }

        // Check if user already exists
        if (users.has(username)) {
            return res.status(409).json({
                success: false,
                message: 'Username already exists. Would you like to log in instead?'
            });
        }

        // Check if email already exists
        for (let user of users.values()) {
            if (user.email === email) {
                return res.status(409).json({
                    success: false,
                    message: 'Email already registered. Would you like to log in instead?'
                });
            }
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 12);

        // Store user with enhanced data
        users.set(username, {
            username,
            email,
            password: hashedPassword,
            createdAt: new Date().toISOString(),
            lastLogin: null,
            profile: {
                company: '',
                role: '',
                bio: ''
            },
            stats: {
                scopesCreated: 0,
                lastActive: new Date().toISOString()
            }
        });

        saveData(users, USERS_FILE);

        // Generate JWT token
        const token = jwt.sign(
            { 
                username,
                email,
                type: 'user'
            }, 
            JWT_SECRET, 
            { expiresIn: '30d' }
        );

        console.log('User registered successfully:', username);

        res.status(201).json({
            success: true,
            message: 'Registration successful! Welcome to FlashGig.',
            user: {
                username,
                email,
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

// Enhanced login
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
                message: 'Username not found. Would you like to sign up instead?'
            });
        }

        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(401).json({
                success: false,
                message: 'Incorrect password. Please try again.'
            });
        }

        // Update user stats
        user.lastLogin = new Date().toISOString();
        user.stats.lastActive = new Date().toISOString();
        saveData(users, USERS_FILE);

        const token = jwt.sign(
            { 
                username: user.username,
                email: user.email,
                type: 'user'
            }, 
            JWT_SECRET, 
            { expiresIn: '30d' }
        );

        res.json({
            success: true,
            message: 'Login successful',
            user: {
                username: user.username,
                email: user.email,
                createdAt: user.createdAt,
                lastLogin: user.lastLogin,
                profile: user.profile,
                stats: user.stats
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

// Scope management endpoints
app.post('/api/scopes/save', authenticateToken, async (req, res) => {
    try {
        const { scopeId, title, data } = req.body;
        const username = req.user.username;

        if (!title || !data) {
            return res.status(400).json({
                success: false,
                message: 'Title and scope data are required'
            });
        }

        const scope = {
            id: scopeId || `scope_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
            title,
            data,
            owner: username,
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
            version: 1
        };

        scopes.set(scope.id, scope);
        
        // Update user stats
        const user = users.get(username);
        if (user && !scopeId) { // Only count new scopes, not updates
            user.stats.scopesCreated += 1;
        }
        
        saveData(scopes, SCOPES_FILE);
        saveData(users, USERS_FILE);

        console.log(`Scope saved: ${scope.id} by ${username}`);

        res.json({
            success: true,
            message: 'Scope saved successfully',
            scope: {
                id: scope.id,
                title: scope.title,
                createdAt: scope.createdAt
            }
        });

    } catch (error) {
        console.error('Scope save error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to save scope'
        });
    }
});

app.get('/api/scopes', authenticateToken, (req, res) => {
    try {
        const username = req.user.username;
        const userScopes = Array.from(scopes.values())
            .filter(scope => scope.owner === username)
            .map(scope => ({
                id: scope.id,
                title: scope.title,
                createdAt: scope.createdAt,
                updatedAt: scope.updatedAt
            }))
            .sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt));

        res.json({
            success: true,
            scopes: userScopes
        });

    } catch (error) {
        console.error('Scope fetch error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch scopes'
        });
    }
});

app.get('/api/scopes/:id', authenticateToken, (req, res) => {
    try {
        const scope = scopes.get(req.params.id);
        
        if (!scope) {
            return res.status(404).json({
                success: false,
                message: 'Scope not found'
            });
        }

        if (scope.owner !== req.user.username) {
            return res.status(403).json({
                success: false,
                message: 'Access denied'
            });
        }

        res.json({
            success: true,
            scope
        });

    } catch (error) {
        console.error('Scope fetch error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch scope'
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

        const tempPassword = Math.random().toString(36).slice(-8);
        user.password = await bcrypt.hash(tempPassword, 12);
        saveData(users, USERS_FILE);

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

// User profile management
app.get('/api/user/profile', authenticateToken, (req, res) => {
    try {
        const user = users.get(req.user.username);
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        res.json({
            success: true,
            profile: {
                username: user.username,
                email: user.email,
                createdAt: user.createdAt,
                lastLogin: user.lastLogin,
                profile: user.profile,
                stats: user.stats
            }
        });

    } catch (error) {
        console.error('Profile fetch error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch profile'
        });
    }
});

app.put('/api/user/profile', authenticateToken, async (req, res) => {
    try {
        const { profile } = req.body;
        const user = users.get(req.user.username);
        
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        user.profile = { ...user.profile, ...profile };
        saveData(users, USERS_FILE);

        res.json({
            success: true,
            message: 'Profile updated successfully',
            profile: user.profile
        });

    } catch (error) {
        console.error('Profile update error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update profile'
        });
    }
});

// Enhanced health check with stats
app.get('/api/health', (req, res) => {
    const memoryUsage = process.memoryUsage();
    
    res.json({
        success: true,
        message: 'FlashGig API is running',
        timestamp: new Date().toISOString(),
        stats: {
            users: users.size,
            scopes: scopes.size,
            memory: {
                used: Math.round(memoryUsage.heapUsed / 1024 / 1024) + 'MB',
                total: Math.round(memoryUsage.heapTotal / 1024 / 1024) + 'MB'
            },
            uptime: Math.round(process.uptime()) + 's'
        },
        version: '1.0.0-alpha'
    });
});

// Admin endpoints (protected)
app.get('/api/admin/stats', authenticateToken, (req, res) => {
    // Simple admin check - in production, use proper roles
    if (req.user.username !== 'admin') {
        return res.status(403).json({
            success: false,
            message: 'Admin access required'
        });
    }

    const usersArray = Array.from(users.values()).map(user => ({
        username: user.username,
        email: user.email,
        createdAt: user.createdAt,
        lastLogin: user.lastLogin,
        stats: user.stats
    }));

    res.json({
        success: true,
        users: usersArray,
        totalUsers: users.size,
        totalScopes: scopes.size
    });
});

// JWT middleware
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

// Error handling middleware
app.use((error, req, res, next) => {
    console.error('Unhandled error:', error);
    res.status(500).json({
        success: false,
        message: 'Something went wrong!'
    });
});

// 404 handler
app.use('*', (req, res) => {
    res.status(404).json({
        success: false,
        message: 'Endpoint not found'
    });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 FlashGig Production API running on port ${PORT}`);
    console.log(`📍 Health: http://localhost:${PORT}/api/health`);
    console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`👥 Users: ${users.size} | 📋 Scopes: ${scopes.size}`);
    console.log(`🔐 JWT: ${JWT_SECRET ? 'Configured' : 'Missing!'}`);
});
