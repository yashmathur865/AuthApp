const bcrypt = require('bcrypt')
const User = require("../models/User")
const jwt = require('jsonwebtoken')
const { response } = require('express')
require("dotenv").config()

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

//login

exports.login = async (req,res) =>{
    try{
        //data fetch
        const {email,password} = req.body
        //validation on email and password
        if(!email || !password){
            return res.status(400).json({
                success:false,
                message:"Please provide email and password"
            })
        }

        //check for registered user user
        let user = await User.findOne({email})
        if(!user){
            return res.status(401).json({
                success:false,
                message:"Not a registered user"
            })
        }

        const payload = {
            email: user.email,
            id: user._id,
            role: user.role
        }
        //Verify password and generate a JWT token
        if(await bcrypt.compare(password,user.password)){
            //password matched
            let token = jwt.sign(payload,
                process.env.JWT_SECRET,
                {
                    expiresIn: "2h" // expires in 24 hours
                }
            )
            
            user=user.toObject();
            user.token = token;
            user.password = undefined;

            const options = {
                expires: new Date(Date.now() + 3 * 60 * 60 * 24*1000), // expires in 24 hours
                httpOnly: true
            }

            res.cookie("yashtoken",token,options).status(200).json({
                success:true,
                token:token,
                message:"User logged in successfully",
                user
            })


        }
        else{
            //password do not match
            return res.status(403).json({
                success:false,
                message:"Invalid password"
            })
        }
    }
    catch(error){
        console.log(error)
            return res.status(500).json({
                success:false,
                message:"User cannot be  logged in",
            })
    }
}