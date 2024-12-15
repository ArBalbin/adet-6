const express = require('express');
const router = express.Router();
const {
    createStudent,
    getStudents,
    getStudentById,
    updateStudent,
    deleteStudent,
} = require('../controller/studentsControllers');
const authenticateToken = require('../middlewares/authMiddleware');

// Route to get all students
router.get('/', authenticateToken, getStudents);

// Route to get a student by ID
router.get('/:student_id', authenticateToken, getStudentById);

// Route to create a new student
router.post('/', authenticateToken, createStudent);

// Route to update a student by ID
router.put('/:student_id', authenticateToken, updateStudent);

// Route to delete a student by ID
router.delete('/:student_id', authenticateToken, deleteStudent);

module.exports = router;
