const express = require('express');
const router = express.Router();
const {
    register,
    login,
    refreshToken,
    getProfile,
    updateProfile,
    changePassword,
    requestPasswordReset,
    resetPassword,
    logout
} = require('../controllers/authController');
const { verifyToken } = require('../middleware/auth');

router.post('/register', register);
router.post('/login', login);
router.post('/refresh-token', refreshToken);
router.post('/request-password-reset', requestPasswordReset);
router.post('/reset-password', resetPassword);

router.get('/profile', verifyToken, getProfile);
router.put('/profile', verifyToken, updateProfile);
router.put('/change-password', verifyToken, changePassword);
router.post('/logout', verifyToken, logout);

module.exports = router;