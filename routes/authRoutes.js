const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('../models/user');

const router = express.Router();

router.post('/register',  async (req, res) => {
    try{
        const {username, password} = req.body;

        // Check if the username already exists
        const existingUser = await User.findOne({username});
        if(existingUser){
            return res.status(400).json({error: "Username alredy exists!"});
        }

        const hashPassword = await bcrypt.hash(password, 10);

        //create new user
        const user = new User({username, password:hashPassword});
        await user.save();

        res.status(201).json({message: "User registered successfully!"});
    }
    catch(err){
        console.log(err);
        res.status(500).json({error: "Internal Server error!"});
    }

});

router.post('/login', async(req, res) => {
    try{
        const {username, password} = req.body;

        //find the user by username
        const user = await User.findOne({username});

        if(!user)
        {
            return res.status(401).json({error: "Invalid Credentials!"});
        }
        //password check
        const passwordMatch = await bcrypt.compare(password, user.password);
        if(!passwordMatch)
        {
            return res.status(401).json({error: "Invalid Credentials!"});

        }

        //generate jwt tokens
        
         const secretKey = process.env.SECRET_KEY || 'fallbacksecretkey';

            // Example of signing a token
            const token = jwt.sign({ userId: 'exampleUserId' }, secretKey, { expiresIn: '1h' });

            // Example of verifying a token
            jwt.verify(token, secretKey, (err, decoded) => {
            if (err) {
                console.error('Invalid token');
            } else {
                console.log('Decoded user:', decoded);
            }
            });

        res.status(200).json({ token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal server error' });
  }
  
});

module.exports = router;