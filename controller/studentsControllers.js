const pool = require('../config/database');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');


// Create a new student
const createStudent = async (req, res) => {
    const { lname, fname, mname, user_id, course_id } = req.body;

    // Debugging: log incoming data
    console.log(req.body);

    // Validate incoming data
    if (!lname || !fname || !mname || !user_id || !course_id) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    try {
        const result = await pool.query(
            'INSERT INTO students (lname, fname, mname, user_id, course_id) VALUES (?, ?, ?, ?, ?)',
            [lname, fname, mname, user_id, course_id]
        );

        res.status(201).json({ message: 'Student created', student_id: result.insertId });
    } catch (err) {
        console.error(err); // Log the error for debugging
        res.status(500).json({ error: err.message });
    }
};


// Get all students
const getStudents = async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM students');
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

// Get a student by ID
const getStudentById = async (req, res) => {
    const { student_id } = req.params;

    try {
        const [rows] = await pool.query('SELECT * FROM students WHERE student_id = ?', [student_id]);

        if (rows.length === 0) {
            return res.status(404).json({ error: 'Student not found' });
        }

        res.json(rows[0]);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'An error occurred while fetching the student.' });
    }
};

// Update a student
const updateStudent = async (req, res) => {
    const { student_id } = req.params;
    const { lname, fname, mname, user_id, course_id } = req.body;

    // Validate incoming data
    if (!lname || !fname || !user_id || !course_id) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    try {
        const [result] = await pool.query(
            'UPDATE students SET lname = ?, fname = ?, mname = ?, user_id = ?, course_id = ? WHERE student_id = ?',
            [lname, fname, mname, user_id, course_id, student_id]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Student not found' });
        }

        res.json({ message: 'Student updated' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

// Delete a student
const deleteStudent = async (req, res) => {
    const { student_id } = req.params;

    try {
        const [result] = await pool.query('DELETE FROM students WHERE student_id = ?', [student_id]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Student not found' });
        }

        res.json({ message: 'Student deleted' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

module.exports = {
    createStudent,
    getStudents,
    getStudentById,
    updateStudent,
    deleteStudent,
};
