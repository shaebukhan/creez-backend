const express = require("express");
const { registerController, loginController, forgotPasswordController, logoutController, resetPasswordController, profileUpdateController, addUserAdminController, getSingleUserController, userUpdateController } = require("../controllers/authController");
const { requireSignIn, isAdmin } = require("../middlewares/authMiddleware");
const router = express.Router();

//Register Route
router.post("/register", registerController);


//login route
router.post("/login", loginController);

//logout
router.post("/logout", logoutController);
//Forgot password 
router.post("/forgot-password", forgotPasswordController);
//reset password 
router.post("/reset-password/:token", resetPasswordController);
//update profile
router.post("/update-profile/:id", requireSignIn, profileUpdateController);
//update user 
router.post("/update-user/:id", requireSignIn, isAdmin, userUpdateController);
//add user by admin 
router.post("/add-user", requireSignIn, isAdmin, addUserAdminController);
//get single user 
router.get("/get-user/:id", requireSignIn, isAdmin, getSingleUserController);

module.exports = router;