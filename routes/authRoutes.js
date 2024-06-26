const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const verifyToken = require('../middleware/authMiddleware');
router.post('/register', authController.register);
router.post('/login', authController.login);
router.get('/user', verifyToken, authController.user);
router.post('/addpost', verifyToken, authController.create);
router.post('/updatepost', verifyToken, authController.update);
router.get('/getposts', verifyToken, authController.getpost);
router.post('/post/:id', verifyToken, authController.deletepost);
router.post('/likes', verifyToken, authController.like);
router.post('/comment', verifyToken, authController.comment);
router.post('/logout', verifyToken, authController.logoutuser);
module.exports = router;