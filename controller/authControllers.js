const pool = require('../config/database');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// Register Endpoint
const register = async (req, res) => {
    const { fullname, username, passwordx } = req.body;

    // Validate input data
    if (!fullname || !username || !passwordx) {
        return res.status(400).json({ error: 'All fields (fullname, username, passwordx) are required' });
    }

    try {
        // Check if username already exists
        const [existingUser] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
        if (existingUser.length > 0) {
            return res.status(400).json({ error: 'Username already taken' });
        }

        // Hash the password
        const hashedPasswordx = await bcrypt.hash(passwordx, 10);

        // Insert user into the database
        await pool.query('INSERT INTO users (fullname, username, passwordx) VALUES (?, ?, ?)', [fullname, username, hashedPasswordx]);

        res.status(201).json({ message: 'User registered successfully' });
    } catch (err) {
        console.error('Error during registration:', err);  // Log the error for debugging
        res.status(500).json({ error: 'Server error during registration', details: err.message });
    }
};

// Login Endpoint
const login = async (req, res) => {
    const { username, passwordx } = req.body;

    // Validate input data
    if (!username || !passwordx) {
        return res.status(400).json({ error: 'Username and password are required' });
    }

    try {
        // Query the database for the user by username
        const [rows] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);

        if (rows.length === 0) {
            return res.status(400).json({ error: 'Invalid username or password' });
        }

        const user = rows[0];

        // Compare the provided password with the hashed password in the database
        const isMatch = await bcrypt.compare(passwordx, user.passwordx);

        if (!isMatch) {
            return res.status(400).json({ error: 'Invalid username or password' });
        }

        // Generate a JWT token
        const token = jwt.sign(
            { user_id: user.user_id, username: user.username },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_ACCESS_EXPIRATION_TIME || '1h' }  // Default to 1 hour if not set
        );

        // Return the JWT token in the response
        res.json({ token });
    } catch (err) {
        console.error('Error during login:', err);  // Log the error
        res.status(500).json({ error: 'Server error during login', details: err.message });
    }
};

module.exports = { register, login };
