const pool = require('../config/database');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');



// Create a new course
const createCourse = async (req, res) => {
    const { user_id, course_code, course_name } = req.body;

    // Validate incoming data
    if (!user_id || !course_code || !course_name) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    try {
        const result = await pool.query(
            'INSERT INTO courses (user_id, course_code, course_name) VALUES (?, ?, ?)',
            [user_id, course_code, course_name]
        );

        res.status(201).json({ message: 'Course created', course_id: result.insertId });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

// Get all courses
const getCourses = async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM courses');
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

// Get a course by ID
const getCourseById = async (req, res) => {
    const { course_id } = req.params;

    try {
        const [rows] = await pool.query('SELECT * FROM courses WHERE course_id = ?', [course_id]);

        if (rows.length === 0) {
            return res.status(404).json({ error: 'Course not found' });
        }

        res.json(rows[0]);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'An error occurred while fetching the course.' });
    }
};

// Update a course
const updateCourse = async (req, res) => {
    const { course_id } = req.params;
    const { user_id, course_code, course_name } = req.body;

    // Validate incoming data
    if (!user_id || !course_code || !course_name) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    try {
        const [result] = await pool.query(
            'UPDATE courses SET user_id = ?, course_code = ?, course_name = ? WHERE course_id = ?',
            [user_id, course_code, course_name, course_id]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Course not found' });
        }

        res.json({ message: 'Course updated' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

// Delete a course
const deleteCourse = async (req, res) => {
    const { course_id } = req.params;

    try {
        const [result] = await pool.query('DELETE FROM courses WHERE course_id = ?', [course_id]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Course not found' });
        }

        res.json({ message: 'Course deleted' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

module.exports = {
    createCourse,
    getCourses,
    getCourseById,
    updateCourse,
    deleteCourse,
};
