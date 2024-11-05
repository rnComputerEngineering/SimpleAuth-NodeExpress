const express = require("express");
const { urlencoded} = require("body-parser");
const bcrypt = require("bcrypt");
const jwtoken = require("jsonwebtoken")
const {readFile,writeFile} = require("fs").promises;
const rateLimit = require("express-rate-limit");
const {body,validationResult} = require("express-validator");

const dataBasePath = "./users.json"; //json is not ideal but it is sufficent for this code example
const secretKey = "123456"; // edit this


const limitLogins = rateLimit({ //5 tries in 15 minutes to prevent brute force
    windowMs: 15* 60 * 1000,
    limit: 5
});

const getUsers = async () => 
{
    try 
    {
        const users = await readFile(dataBasePath, "utf8");
        return JSON.parse(users);
    } 
    catch (error) 
    {
        console.log(error);
        return [];
    }
}

const addNewUser = async (username,password) => 
{
    try 
    {
        let users = await getUsers();
        const luckyNumber = Math.floor(Math.random()*100);
        users.push({username,password,luckyNumber});
        await writeFile(dataBasePath,JSON.stringify(users,null,2));
        return true;
    } 
    catch (error) 
    {
        console.log("Error adding new user. Error:",error);
        return false;
    }
}

const checkToken = (req,res,next) => 
{
    const token = req.headers["authorization"];
    if(!token)
    {
        return res.status(401).json({message:"Please login to proceed"});
    }
    jwtoken.verify(token,secretKey, (err,decoded) => 
    {
        if(err)
        {
            return res.status(401).json({ message: "Token expired or invalid" });
        }
        req.user = decoded; // storing data in request
        next();
    });
}


const app = express();


app.use(express.json());
app.use(urlencoded({extended:false}));

app.post("/signup",
    [body("username").isString().withMessage("Username must be string")
        .isLength({min:2,max:30}).withMessage("Username must be between 2-30 characters")
        .isAlphanumeric().withMessage("Username must only contain letters and numbers"),
    body("password").isLength({min:8,max:128}).withMessage("Password must be between 8-128 characters")
        .matches(/\d/).withMessage("Password must contain at least one number")
        .matches(/[a-z]/).withMessage("Password must contain at least one lowercase letter")
        .matches(/[A-Z]/).withMessage("Password must contain at least one uppercase letter")
    ],
    async (req,res) => 
{
    const errors = validationResult(req);
    if(!errors.isEmpty())
    {
        return res.status(400).json({errors:errors.array()});
    }
    const {username,password} = req.body;
    console.log(username,password);
    const users = await getUsers();
    if(users.find(user => user.username === username))
    {
        return res.status(400).json({message:"Username is taken"});
    }
    const hashedPass = await bcrypt.hash(password, 12);
    const result = await addNewUser(username,hashedPass);
    if(result === true){
        res.status(201).json({message:"User added succesfully"});
    }
    else{
        res.status(500).json({message:"An error occurred during signup"});
    }
});

app.post("/login",
    [body("username").isLength({min:2,max:30}).withMessage("Invalid username"),
     body("password").isLength({min:8,max:128}).withMessage("Invalid password")
    ],
limitLogins, async (req,res) => 
{
    const errors = validationResult(req);
    if(!errors.isEmpty())
    {
        return res.status(400).json({errors:errors.array()});
    }
    const {username,password} = req.body;
    const users = await getUsers();
    const user = users.find(user => user.username === username);
    
    if(user && await bcrypt.compare(password,user.password))
    {
        const token = jwtoken.sign({username},secretKey,{expiresIn:"1h"});
        return res.status(202).json({token});
    }
    else
    {
        return res.status(400).json({message:"Invalid username or password"});
    }
});

app.delete("/logout",checkToken,(req,res) => 
{
    //token must be removed in frontend after this
    res.status(200).json({message:"Logged out"})
});

app.get("/private_route",checkToken, async (req,res) => 
{
    const users = await getUsers();
    const user = users.find( (user) => user.username == req.user.username)
    if(!user)
    {
        return res.status(404).json({message:"Cannot find user"});
    }
    res.status(200).json({message:`Welcome ${user.username}. Your lucky number is ${user.luckyNumber}`});
});

app.listen(5000);
