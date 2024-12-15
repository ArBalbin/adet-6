const express = require('express');
const router = express.Router();
const {createDepartment,getDepartments,getDepartmentById,updateDepartment,deleteDepartment,} = require('../controller/deptControllers');
const authenticateToken = require('../middlewares/authMiddleware');

router.get('/', authenticateToken, getDepartments );
router.get('/:id', authenticateToken, getDepartmentById );
router.post('/', authenticateToken, createDepartment );
router.put('/:id', authenticateToken, updateDepartment  );
router.delete('/:id', authenticateToken, deleteDepartment);

module.exports = router;
