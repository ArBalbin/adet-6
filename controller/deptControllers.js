const pool = require('../config/database');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');


// Create a new department
const createDepartment = async (req, res) => {
    const { user_id, dept_code, dept_name } = req.body;

    // Validate incoming data
    if (!user_id || !dept_code || !dept_name) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    try {
        const result = await pool.query(
            'INSERT INTO departments (user_id, dept_code, dept_name) VALUES (?, ?, ?)',
            [user_id, dept_code, dept_name]
        );

        res.status(201).json({ message: 'Department created', dept_id: result.insertId });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

// Get all departments
const getDepartments = async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM departments');
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

// Get a department by ID
const getDepartmentById = async (req, res) => {
    const { id } = req.params; // Change dept_id to id

    try {
        const [rows] = await pool.query('SELECT * FROM departments WHERE dept_id = ?', [id]);

        if (rows.length === 0) {
            return res.status(404).json({ error: 'Department not found' });
        }

        res.json(rows[0]);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'An error occurred while fetching the department.' });
    }
};

// Update a department
const updateDepartment = async (req, res) => {
    const { id } = req.params; // Change dept_id to id
    const { user_id, dept_code, dept_name } = req.body;

    // Validate incoming data
    if (!user_id || !dept_code || !dept_name) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    try {
        const [result] = await pool.query(
            'UPDATE departments SET user_id = ?, dept_code = ?, dept_name = ? WHERE dept_id = ?',
            [user_id, dept_code, dept_name, id] // Use id here
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Department not found' });
        }

        res.json({ message: 'Department updated' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

// Delete a department
const deleteDepartment = async (req, res) => {
    const { id } = req.params; // Change dept_id to id

    try {
        const [result] = await pool.query('DELETE FROM departments WHERE dept_id = ?', [id]); // Use id here

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Department not found' });
        }

        res.json({ message: 'Department deleted' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};


module.exports = {
    createDepartment,
    getDepartments,
    getDepartmentById,
    updateDepartment,
    deleteDepartment,
};
