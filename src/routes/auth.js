require('dotenv').config();

const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('../../config/database');
const authenticateJWT = require('../middleware/auth');
const {body, validationResult} = require('express-validator');

//Helper - generate JWT token 
/*function generateToken(user){
    return jwt.sign(
        {id: user.id, username: user.username, role_id: user.role_id},
        process.env.JWT_SECRET,
        { expiresIn: '1h'}
    );
}*/

function generateAccessToken(user) {
    return jwt.sign(
        { 
            id: user.id,
            username: user.username,
            role_id: user.role_id,
        },
        process.env.JWT_SECRET,
        {
            expiresIn: parseInt(process.env.JWT_ACCESS_EXPIRY) || '15m'
        }
    );
}

function generateRefreshToken(user) {
    return jwt.sign(
        { 
            id: user.id,
        },
        process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET,
        {
            expiresIn: parseInt(process.env.JWT_REFRESH_EXPIRY) || '7d'
        }
    );
}



//User registration
router.post(
    '/register',
    [
        body('username')
            .trim()
            .isLength({ min: 8, max:32 }). withMessage('Username must be 3-20 Characters')
            .matches(/^[a-zA-Z0-9_-]+$/).withMessage('Username can only contain letters, numbers, _, -'),
        body('email')
            .isEmail().withMessage('Valid Email Required')
            .normalizeEmail(),
        body('password')
            .isLength({min: 8, max: 32}).withMessage('Password must be at least 8 characters')
            .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/).withMessage('Password must contain uppercase, lowercase, and number'),
    ],
    (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({errors: errors.array()});
        }
        const {username, email, password} = req.body;

        db.get('SELECT * FROM Users WHERE username = ? OR email = ?', [username, email],
            (err, user) => {
                console.log('Existing User:', user);
                if (err) return res.status(500).json({ error: 'Database error'});
                if (user) return res.status(400).json({ error: 'User already Exists'});

                //Hash Password
                bcrypt.hash(password, 10, (err, hashedPassword) =>{
                    if (err) return res.status(500).json({ error: 'Error hashing password'});
                
                    //Default role as viewer (role_id = 3)
                    const role_id = 3;

                    db.run(
                        'INSERT INTO Users (username, email, password, role_id) VALUES (?,?,?,?)',
                        [username, email, hashedPassword, role_id],
                        function (err) {
                            if (err) return res.status(500).json({ error: 'Insert user failed', details: err.message});
                            const user = {
                                id: this.lastID,
                                username,
                                email, 
                                role_id,
                            };
                            const accessToken = generateAccessToken(user);
                            res.status(201).json({ message: 'User registered succesfully', accessToken});
                        }
                    );
                });
            }
        );
    }
);

//User login
router.post(
    '/login',
    [
        body('username')
            .notEmpty().withMessage('Username Required')
            .isLength({ min: 8, max:32 }). withMessage('Username must be 3-20 Characters')
            .matches(/^[a-zA-Z0-9_-]+$/).withMessage('Username can only contain letters, numbers, _, -'),
        body('password')
            .notEmpty().withMessage('Password required')
            .isLength({min: 8, max: 32}).withMessage('Password must be at least 8 characters')
            .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/).withMessage('Password must contain uppercase, lowercase, and number'),
    ],
    (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array()});
        }

        const {username, password} = req.body;

        db.get(
            'SELECT * FROM Users WHERE username = ?', [username], (err, user) => {
                if (err) return res.status(500).json({ error: 'Database Error'});
                if (!user) return res.status(400).json({ error: 'Invalid username or password'});

                bcrypt.compare(password, user.password, (err, isMatch) => {
                    if (err) return res.status(500).json({ error: 'Password comparison error'});
                    if (!isMatch) return res.status(400).json({ error: 'Invalid username or password'});

                    const accessToken = generateAccessToken(user);
                    const refreshToken = generateRefreshToken(user);

                    db.run('UPDATE Users SET refresh_token = ? WHERE id =?', [refreshToken,user.id]);
                    res.cookie('refreshToken', refreshToken, {
                        httpOnly: true,
                        secure: process.env.NODE_ENV === 'production',
                        sameSite: 'Strict',
                        maxAge: parseInt(process.env.JWT_REFRESH_EXPIRY) * 1000,
                    });
                    res.json({message: 'Login successful', accessToken});
                });
            }
        );
    }
);

router.post('/token', (req, res) =>{
    const refreshToken = req.cookies.refreshToken;
    if (!refreshToken) return res.status(401).json({error: 'Refresh token missing'});

    jwt.verify(refreshToken, process.env.JWT_REFRESH_TOKEN || process.env.JWT_SECRET, (err, decoded) => {
        if (err) return res.status(403).json({ error: 'Invalid refresh token'});
        db.get(' SELECT refresh_token FROM Users where id = ?', [decoded.id], (err, row) =>{
            if (err || !row || row.refresh_token !== refreshToken) {
                return res.status(403).json({error: 'Refresh token revoked'});
            }
            const accessToken = generateAccessToken({ id: decoded.id});
            res.json({accessToken})
        });
    });
});

router.post('/logout', authenticateJWT, (req, res) => {
    db.run('UPDATE Users SET refresh_token = NULL where id = ?', [req.user.id], (err) => {
        if (err) return res.status(500).json({ error: 'Logout failed'});
        
        res.clearCookie('refreshToken',{
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'Strict'
        });
        res.json({message: 'Logged out successfully'})
    });
});

module.exports = router;