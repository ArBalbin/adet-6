const pool = require('../config/database'); 
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');


// Get all users
const getAllUsers = async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT user_id, fullname, username FROM users');
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

// Get user by ID
const getUserById = async (req, res) => {
    const { id } = req.params; 

    try {
        const [rows] = await pool.query('SELECT user_id, fullname, username FROM users WHERE user_id = ?', [id]);

        if (rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json(rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

// Create a new user
const createUser = async (req, res) => {
    const { fullname, username, passwordx } = req.body;

    try {
        const hashedPasswordx = await bcrypt.hash(passwordx, 10);
        await pool.query('INSERT INTO users (fullname, username, passwordx) VALUES (?, ?, ?)', [fullname, username, hashedPasswordx]);

        res.status(201).json({ message: 'User created' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

// Update a user
const updateUser = async (req, res) => {
    const { id } = req.params; // User ID from route parameters
    const { fullname, username, passwordx } = req.body;

    try {
        
        const hashedPasswordx = passwordx ? await bcrypt.hash(passwordx, 10) : undefined;

        await pool.query(
            'UPDATE users SET fullname = ?, username = ?, passwordx = ? WHERE user_id = ?',
            [fullname, username, hashedPasswordx, id]
        );

        res.json({ message: 'User updated' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

// Delete a user
const deleteUser = async (req, res) => {
    const { id } = req.params; // User ID from route parameters

    try {
        const result = await pool.query('DELETE FROM users WHERE user_id = ?', [id]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json({ message: 'User deleted' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

// Export the controller functions
module.exports = {
    getAllUsers,
    getUserById,
    createUser,
    updateUser,
    deleteUser,
};
