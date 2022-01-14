const express = require('express');
const User = require('../models/User')
const router = express.Router();
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
var jwt = require('jsonwebtoken');
const fetchuser = require('../middleware/fetchuser');


const JWT_SECRET = 'Tomisagoodb$oy';

// ROUTE 1 : creating user using:POST endpoint:"/api/auth/createuser"
router.post('/createuser',[
    body('name','Enter a valid name').isLength({ min: 3 }),
    body('email','Enter a valid email').isEmail(),
    body('password','password must be atleast 5 characters').isLength({ min: 5 }),
], async (req,res)=>{
  //returns bad requests and errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
   
   
    try{
       //check whether user with this same email exists already
    let user = await User.findOne({email:req.body.email});
    if(user){
      return res.status(400).json({error:"Sorry a user with this email already exists"})
    }
    //hashing password
    const salt = await bcrypt.genSalt(10);
    secPass = await bcrypt.hash(req.body.password,salt)

    //creating new user
     user = await User.create({
        name: req.body.name,
        password: secPass,
        email: req.body.email,
      });
     const data = {
        user:{
          id: user.id
        }
      }

      const authToken = jwt.sign(data,JWT_SECRET);
     
      // res.json(user)
      res.json({authToken});
}
catch(error){
  console.log(error.message);
  res.status(500).send("Some Error occured");
}
})

//ROUTE 2: authenticating a user using:POST endpoint:"/api/auth/login"

router.post('/login',[
  body('email','Enter a valid email').isEmail(),
  body('password','Password can not be blank').exists(),
], async (req,res)=>{
  //returns bad requests and errors
  const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const {email, password } = req.body;
    try {
      let user = await User.findOne({email});
      if(!user){
        return res.status(400).json({error:"Please try to login with correct credentials"});
      }
      const passwordCompare = await bcrypt.compare(password,user.password);
      if(!passwordCompare){
        return res.status(400).json({error:"Please try to login with correct credentials"});
      }

      const data = {
        user:{
          id: user.id
        }
      }
      const authToken = jwt.sign(data,JWT_SECRET);
      res.json({authToken});
    } catch (error) {
      console.log(error.message);
      res.status(500).send("Internal server error");
    }

})

//ROUTE 3 : get logged in user details using POST "/api/auth/getuser"
router.post('/getuser',fetchuser,async (req,res)=>{

try {
  userId = req.user.id;
  const user = await User.findById(userId).select("-password")
  res.send(user);
} catch (error) {
  console.log(error.message);
      res.status(500).send("Internal server error");
}
})

module.exports =  router