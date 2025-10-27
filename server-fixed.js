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
        "https://flashgig-backend.onrender.com",
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

// File-based database with better error handling
const USERS_FILE = path.join(__dirname, 'users.json');

// Enhanced data loading with backups
function loadUsers() {
    try {
        if (fs.existsSync(USERS_FILE)) {
            const data = fs.readFileSync(USERS_FILE, 'utf8');
            if (!data.trim()) {
                console.log('Users file is empty, starting fresh...');
                return new Map();
            }
            const usersArray = JSON.parse(data);
            
            // Ensure all users have the required properties
            const usersMap = new Map();
            usersArray.forEach(([username, userData]) => {
                // Backward compatibility: ensure stats exist
                if (!userData.stats) {
                    userData.stats = {
                        scopesCreated: 0,
                        lastActive: new Date().toISOString()
                    };
                }
                usersMap.set(username, userData);
            });
            
            return usersMap;
        }
    } catch (error) {
        console.error('Error loading users:', error.message);
        // Create backup of corrupted file
        if (fs.existsSync(USERS_FILE)) {
            try {
                const backupName = `${USERS_FILE}.corrupted.${Date.now()}`;
                fs.renameSync(USERS_FILE, backupName);
                console.log(`Created backup of corrupted file: ${backupName}`);
            } catch (backupError) {
                console.error('Could not create backup:', backupError.message);
            }
        }
    }
    return new Map();
}

function saveUsers(users) {
    try {
        const usersArray = Array.from(users.entries());
        const tempFile = `${USERS_FILE}.tmp`;
        
        // Write to temporary file first
        fs.writeFileSync(tempFile, JSON.stringify(usersArray, null, 2));
        
        // Then rename to actual file (atomic operation)
        fs.renameSync(tempFile, USERS_FILE);
        
        console.log(`Users saved successfully (${users.size} records)`);
        return true;
    } catch (error) {
        console.error('Error saving users:', error.message);
        return false;
    }
}

// Initialize data stores
const users = loadUsers();
console.log(`Loaded ${users.size} existing users`);

// JWT Secret from environment
const JWT_SECRET = process.env.JWT_SECRET || 'flashgig-fallback-secret-for-development';
if (!process.env.JWT_SECRET) {
    console.warn('⚠️  JWT_SECRET environment variable is not set! Using fallback secret.');
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

        const saveSuccess = saveUsers(users);
        if (!saveSuccess) {
            return res.status(500).json({
                success: false,
                message: 'Failed to save user data'
            });
        }

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
            message: 'Internal server error: ' + error.message
        });
    }
});

// FIXED: Enhanced login with stats safety check
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

        // Update user stats with safety check
        user.lastLogin = new Date().toISOString();
        
        // Ensure stats object exists
        if (!user.stats) {
            user.stats = {
                scopesCreated: 0,
                lastActive: new Date().toISOString()
            };
        } else {
            user.stats.lastActive = new Date().toISOString();
        }
        
        const saveSuccess = saveUsers(users);
        if (!saveSuccess) {
            console.error('Failed to save user login data');
        }

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
                profile: user.profile || {},
                stats: user.stats || { scopesCreated: 0, lastActive: new Date().toISOString() }
            },
            token
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error: ' + error.message
        });
    }
});

// FIXED: Forgot password endpoint with stats safety check
app.post('/api/auth/forgot-password', async (req, res) => {
    try {
        const { username } = req.body;

        console.log('Forgot password request for:', username);

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
        console.log(`Generated temp password for ${username}: ${tempPassword}`);

        // Hash and update the password
        user.password = await bcrypt.hash(tempPassword, 12);
        
        // Ensure stats object exists
        if (!user.stats) {
            user.stats = {
                scopesCreated: 0,
                lastActive: new Date().toISOString()
            };
        } else {
            user.stats.lastActive = new Date().toISOString();
        }
        
        // Save to file with error handling
        const saveSuccess = saveUsers(users);
        if (!saveSuccess) {
            return res.status(500).json({
                success: false,
                message: 'Failed to save password reset. Please try again.'
            });
        }

        console.log(`Password reset successful for ${username}`);
        
        res.json({
            success: true,
            message: `Your temporary password is: ${tempPassword} - Use this to login and change your password immediately.`,
            tempPassword: tempPassword
        });

    } catch (error) {
        console.error('Forgot password error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error: ' + error.message
        });
    }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
    const memoryUsage = process.memoryUsage();
    
    res.json({
        success: true,
        message: 'FlashGig API is running',
        timestamp: new Date().toISOString(),
        stats: {
            users: users.size,
            memory: {
                used: Math.round(memoryUsage.heapUsed / 1024 / 1024) + 'MB',
                total: Math.round(memoryUsage.heapTotal / 1024 / 1024) + 'MB'
            },
            uptime: Math.round(process.uptime()) + 's'
        },
        version: '1.0.0-alpha'
    });
});

// Get user profile (protected)
app.get('/api/auth/profile', (req, res) => {
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

        const userData = users.get(user.username);
        if (!userData) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        res.json({
            success: true,
            user: {
                username: userData.username,
                email: userData.email,
                createdAt: userData.createdAt,
                lastLogin: userData.lastLogin,
                profile: userData.profile || {},
                stats: userData.stats || { scopesCreated: 0, lastActive: new Date().toISOString() }
            }
        });
    });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 FlashGig Fixed API running on port ${PORT}`);
    console.log(`📍 Health: http://localhost:${PORT}/api/health`);
    console.log(`✅ Fixed: Stats safety checks implemented`);
});
