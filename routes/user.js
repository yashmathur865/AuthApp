const express = require('express');
const router = express.Router();

const {signup,login} = require('../Controllers/Auth');
const {auth, isStudent,isAdmin} = require('../middlewares/auth');

router.post('/login',login);
router.post('/signup', signup);

//Protected Routes
router.get('/student', auth, isStudent, (req,res)=>{
    res.json({
        success: true,
        message: "Welcome to the protected route for students"
    })
});

router.get('/admin', auth, isAdmin, (req,res)=>{
    res.json({
        success: true,
        message: "Welcome to the protected route for Admin"
    })
});



module.exports = router;
