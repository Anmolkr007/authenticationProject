
const express = require('express')
const connectDB = require('./db/index.js')
const User = require('./models/user.js')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const cookieParser = require('cookie-parser');


const app = express()
app.use(cookieParser());
require('dotenv').config()
app.set('view engine', 'ejs');     // Set EJS as the template engine
app.set('views', './views');       // (Optional) Specify the views folder

app.use(express.urlencoded({ extended: true }));  // To parse form data
app.use(express.json());

connectDB();









app.get('/register', (req, res) => {
    res.render('register',{message:''});
})

app.post('/register',async (req,res)=>{
  try {
    const {username,password} = req.body;
    const UserFind = await User.findOne({username});
    if(UserFind){
      return res.render('register', { message: 'User already exists' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({
      username,
      password:hashedPassword
    })
    await newUser.save();
    res.render('register', { message: 'User registered successfully!' });
  } catch (error) {
    res.render('register', { message: 'Server error. Try again.' });
  }
})

app.get('/login',(req,res)=>{
  res.render('login',{message:''});
})

app.post('/login',async (req,res)=>{
  try {
    const {username,password} = req.body;
    const user = await User.findOne({username});
    if (!user) {
      return res.render('login', { message: 'User not found' });
    }


    const isMatch = await bcrypt.compare(password, user.password);


    if (!isMatch) {
      return res.render('login', { message: 'Incorrect password' });
    }

    const token = jwt.sign(
    { userId: user._id,
      username:user.username
     }, 
    process.env.JWT_SECRET, 
    { expiresIn: '10s' }
    );

    res.cookie('token', token, {
      httpOnly: true,
      maxAge: 10000, // 1 hour3600000
    });

    res.redirect('/dashboard');

  } catch (error) {
    console.log('error while login')
  }
})
function authenticateToken(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.redirect('/login');

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded; // Add user info to request
    next();
  } catch (err) {
    return res.redirect('/login');
  }
}


app.get('/dashboard', authenticateToken, (req, res) => {
  res.render('dashboard', {
    username: req.user.username,
    quote: 'Keep coding, keep growing!',
    date: new Date().toDateString(),
    
  });
});
app.get('/logout', (req, res) => {
  res.clearCookie('token');
  res.redirect('/login');
});


app.listen(process.env.PORT, () => {
  console.log(`Example app listening on port ${process.env.PORT}`)
})
