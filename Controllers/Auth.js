const bcrypt = require('bcrypt')
const User = require("../models/User")

//signup route handler

exports.signup = async (req,res) =>{
    try{
        // get all data
        const {name,email,password,role} = req.body

        // if user already exist
        const existingUser = await User.findOne({email})
        if(existingUser){
            return res.status(500).json({
                success:false,
                message:"User already exist" 
            })
        }

        // secure password
        let hashedPassword;
        try{
            hashedPassword = await bcrypt.hash(password,10) 
        }
        catch(error){
            return res.status(500).json({
                success:false,
                message:"Error while hashing password"
            })
        }

        // create new user
        const newUser = await User.create({
            name,email,password:hashedPassword,role
        })

        return res.json({
            success:true,
            message:"User created successfully",
        })
    }
    catch(error){
        console.error(error);
        return res.json({
            success:false,
            message:"User cannot be  created",
        })
    }
}