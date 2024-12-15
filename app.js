const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');


const authRoutes = require('./routes/authRoutes');
const userRoutes = require('./routes/userRoutes');
const deptRoutes = require('./routes/deptRoutes'); 
const courseRoutes = require('./routes/courseRoutes');
const studentsRoutes = require ('./routes/studentsRoutes');


const app = express();
app.use(bodyParser.json());
app.use(cors());

app.get('/', function (req, res) {
    res.send("Balbin A, CS");
});


app.use('/api/auth', authRoutes);
app.use('/api/user', userRoutes);
app.use('/api/departments', deptRoutes); 
app.use('/api/courses', courseRoutes);
app.use('/api/students', studentsRoutes);


const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});