const express = require('express');
const router = express.Router();
const {
    createCourse,
    getCourses,
    getCourseById,
    updateCourse,
    deleteCourse,
} = require('../controller/courseControllers');
const authenticateToken = require('../middlewares/authMiddleware');

// Route to get all courses
router.get('/', authenticateToken, getCourses);

// Route to get a course by ID
router.get('/:course_id', authenticateToken, getCourseById);

// Route to create a new course
router.post('/', authenticateToken, createCourse);

// Route to update a course by ID
router.put('/:course_id', authenticateToken, updateCourse);

// Route to delete a course by ID
router.delete('/:course_id', authenticateToken, deleteCourse);

module.exports = router;
