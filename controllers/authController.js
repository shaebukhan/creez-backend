const { hashPassword, comparePassword, generateTokenAndSetCookie, getFormattedDateTime, generateRandomString } = require("../helpers/authHelper");
const UserModel = require("../models/UserModel");
const JWT = require("jsonwebtoken");
const nodemailer = require('nodemailer');
const crypto = require("crypto");
const createTransporter = require("../config/emailConfig");


//Register 
const registerController = async (req, res) => {
    try {
        const { name, email, password } = req.body;

        // Validation
        if (!name) {
            return res.send({ message: "Le nom est requis" });
        }
        if (!email) {
            return res.send({ message: "L'email est requis" });
        }
        if (!password) {
            return res.send({ message: "Le mot de passe est requis" });
        }

        // Vérifier si l'utilisateur existe déjà
        const existingUser = await UserModel.findOne({ email });
        if (existingUser) {
            return res.status(200).send({
                success: false,
                message: "Email déjà enregistré !! Veuillez vous connecter"
            });
        }

        // Hash le mot de passe
        const hashedPassword = await hashPassword(password);
        // Créer le nouvel utilisateur
        const user = await new UserModel({
            name,
            email,
            password: hashedPassword,
        }).save();

        res.status(201).send({
            success: true,
            message: "Compte créé avec succès",
        });
    } catch (error) {
        console.log(error);
        res.status(500).send({
            success: false,
            message: "Erreur lors de l'inscription",
            error
        });
    }
};


// LOGIN 
const loginController = async (req, res) => {
    try {
        const { email, password } = req.body;

        // Check if email and password are provided
        if (!email || !password) {
            return res.status(201).send({
                success: false,
                message: "Email and Password are required",
            });
        }

        // Find user by email
        const user = await UserModel.findOne({ email });
        if (!user) {
            return res.status(201).send({
                success: false,
                message: " E-mail introuvable",
            });
        }

        // Check if password matches
        const isMatch = await comparePassword(password, user.password);
        if (!isMatch) {
            return res.status(201).send({
                success: false,
                message: "Identifiants invalides",
            });
        }

        // Generate JWT token
        const token = await generateTokenAndSetCookie(res, user._id);
        res.status(200).send({
            success: true,
            message: "Connecté avec succès !",
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                role: user.role,
            },
            token
        });
    } catch (error) {
        console.error("Erreur de connexion", error);
        res.status(500).send({
            success: false,
            message: "Erreur de connexion",
            error: error.message,
        });
    }
};

//logout 
const logoutController = async (req, res) => {
    res.clearCookie("token");
    res.status(201).send({
        success: true,
        message: "Déconnexion réussie !",

    });
};
//forgot password Controller 

const forgotPasswordController = async (req, res) => {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(200).send({
                success: false,
                message: "Email is Required"
            });
        }

        // check email and answer 
        const user = await UserModel.findOne({ email });
        //validation 
        if (!user) {
            return res.status(200).send({
                success: false,
                message: "Email Not Found"
            });
        }
        const resetToken = crypto.randomBytes(20).toString("hex");
        const resetTokenExpiresAt = Date.now() + 1 * 60 * 60 * 1000; // 1 hour

        user.resetPasswordToken = resetToken;
        user.resetPasswordExpiresAt = resetTokenExpiresAt;

        await user.save();
        await forgotPasswordEmail(user.email, user.name, `${process.env.CLIENT_URL}/reset-password/${resetToken}`);

        return res.status(200).send({
            success: true,
            message: "Password reset link sent to your email !"
        });
    } catch (error) {
        console.log(error);
        res.status(500).send({
            success: false,
            message: "Error in sending rest password link",
            error
        });
    }
};
//reset password controller
const resetPasswordController = async (req, res) => {
    try {
        const { token } = req.params;
        const { password } = req.body;
        // check email and answer 
        const user = await UserModel.findOne({
            resetPasswordToken: token,
            resetPasswordExpiresAt: { $gt: Date.now() },
        }
        );
        //validation 
        if (!user) {
            return res.status(200).send({
                success: false,
                message: "Invalid Token or Reset Link Expired !!"
            });
        }

        // Hash the password
        const hashedPassword = await hashPassword(password);
        user.password = hashedPassword;
        user.resetPasswordToken = undefined;
        user.resetPasswordExpiresAt = undefined;
        await user.save();
        const { date, time } = getFormattedDateTime();
        await resetPasswordEmail(user.email, user.name, time, date);

        return res.status(200).send({
            success: true,
            message: "Password Changed Successfully !"
        });
    } catch (error) {
        console.log(error);
        res.status(500).send({
            success: false,
            message: "Error in changing password ",
            error
        });
    }
};

const getAlluserController = async (req, res) => {
    try {
        // Find all users with role == 0 and exclude the password field
        const users = await UserModel.find({ role: 0 }).select("-password");


        if (!users || users.length === 0) {
            return res.status(204).json({ success: false, message: "No users found" });
        }

        res.status(200).json({ success: true, users });
    } catch (error) {
        console.log("Error in getting users: ", error);
        res.status(400).json({ success: false, message: error.message });
    }
};

const profileUpdateController = async (req, res) => {

    try {
        const { id } = req.params;
        const { name, email, password } = req.body;
        // Find the user by ID
        const user = await UserModel.findById(id);

        if (!user) {
            return res.status(204).json({ success: false, message: 'Utilisateur introuvable !' });
        }

        // Update name and email
        user.name = name;
        user.email = email;

        // If password is provided, hash and update it
        if (password) {
            const hashedPassword = await hashPassword(password);

            user.password = hashedPassword;
        }

        // Save the updated user data
        await user.save();

        // Respond with success
        res.json({
            success: true,
            message: 'Profil mis à jour avec succès',
            user: {
                name: user.name,
                email: user.email,
            },
        });
    } catch (error) {
        console.error('Erreur lors de la mise à jour du profil', error);
        res.status(500).json({ success: false, message: 'Erreur de serveur' });
    }

};

//add account by admin

const addUserAdminController = async (req, res) => {
    try {
        const { name, email, password } = req.body;

        // Validation
        if (!name) {
            return res.send({ message: "Name is Required" });
        }
        if (!email) {
            return res.send({ message: "Email is Required" });
        }
        if (!password) {
            return res.send({ message: "Password is Required" });
        }

        // Check if the user already exists
        const existingUser = await UserModel.findOne({ email });
        if (existingUser) {
            return res.status(200).send({
                success: false,
                message: "Email Already Registered !!"
            });
        }

        // Hash the password
        const hashedPassword = await hashPassword(password);


        // Create the new user
        const user = await new UserModel({
            name,
            email,
            password: hashedPassword,
            isVerified: true,

        }).save();

        res.status(201).send({
            success: true,
            message: "User Added  Successfully !",
            user,
        });
    } catch (error) {
        console.log(error);
        res.status(500).send({
            success: false,
            message: "Error in Adding user",
            error
        });
    }
};

//get single user

const getSingleUserController = async (req, res) => {
    try {
        const { id } = req.params; // Extract the user ID from the route parameter

        // Find the user by ID
        const user = await UserModel.findById(id);

        if (!user) {
            return res.status(204).json({ success: false, message: 'Account not found' });
        }

        // Respond with success
        res.json({
            success: true,
            user
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
};

//update user

const userUpdateController = async (req, res) => {
    try {
        const { id } = req.params; // Extract the user ID from the route parameter
        const { name, email, password, status } = req.body; // Extract fields from request body

        // Validate required fields
        if (!name || !email) {
            return res.status(400).json({ success: false, message: 'Name and email are required.' });
        }

        // Validate email format (basic validation)
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ success: false, message: 'Invalid email format.' });
        }

        // Validate status if provided
        if (status !== undefined) {
            if (![0, 1].includes(status)) {
                return res.status(400).json({ success: false, message: 'Invalid status value. Must be 0 (Active) or 1 (Locked).' });
            }
        }

        // Find the user by ID
        const user = await UserModel.findById(id);

        if (!user) {
            return res.status(404).json({ success: false, message: 'Account not found.' });
        }

        // Update name and email
        user.name = name;
        user.email = email;

        // If password is provided, hash and update it
        if (password) {
            // Assuming hashPassword is a function that hashes the password
            const hashedPassword = await hashPassword(password);
            user.password = hashedPassword;
        }

        // If status is provided, update it
        if (status !== undefined) {
            user.status = status;
        }

        // Save the updated user data
        await user.save();

        // Respond with success and the updated user data
        res.json({
            success: true,
            message: 'Profile updated successfully.',
            user: {
                name: user.name,
                email: user.email,
                status: user.status, // Include status in the response
            },
        });
    } catch (error) {
        console.error('Error updating profile:', error);
        res.status(500).json({ success: false, message: 'Server error.' });
    }
};


const forgotPasswordEmail = async (email, name, resetToken) => {
    // Configure the email transport using nodemailer
    const transporter = createTransporter();

    // Email options
    const mailOptions = {
        from: process.env.AUTH_EMAIL_P,
        to: email,
        subject: 'PQS Alert',
        html: `<div style="background: #0E2340; padding: 20px; text-align: center;">
    <h1 style="color: white; margin: 0;">PQS</h1>
</div>
<div style="background-color: #f9f9f9; padding: 20px; border-radius: 0 0 5px 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1);">
    <h5 style="font-size:20px">Dear <span style="text-transform:uppercase;">${name}</span>,</h5>
    <p style="font-size:17px">PQS recently received a request for a forgotten password.</p>
    <p style="font-size:17px">To change your PQS password, please click on below link</p>
    <div style="text-align: center; margin: 30px 0;">
        <a href="${resetToken}" style="font-size: 20px; font-weight: bold; background: #0E2340; color: #fff; padding: 10px 30px; border-radius: 5px; text-decoration: none;">Reset your password</a>
    </div>
     
    <p style="font-size:17px">The Link will expire in 1 hour for security reasons.</p>
    <p style="font-size:17px">If you did not request this change, you do not need to do anything.</p>
    <h5 style="font-size:17px">Best regards,<br>PQS Team</h5>
     
</div>
<div style="text-align: center; margin-top: 20px; color: #888; font-size: 13px;">
    <p>This is an automated message, please do not reply to this email.</p>
</div>
`
    };

    // Send the email
    await transporter.sendMail(mailOptions);
};

const resetPasswordEmail = async (email, name, time, date) => {
    // Configure the email transport using nodemailer
    const transporter = createTransporter();


    // Email options
    const mailOptions = {
        from: process.env.AUTH_EMAIL_P,
        to: email,
        subject: 'PQS Alert',
        html: `<div style="background: #0E2340; padding: 20px; text-align: center;">
    <h1 style="color: white; margin: 0;">PQS</h1>
</div>
<div style="background-color: #f9f9f9; padding: 20px; border-radius: 0 0 5px 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1);">
    <h5 style="font-size:20px">Dear <span style="text-transform:uppercase;">${name}</span>,</h5>
    <p style="font-size:17px">You have successfully changed  your password  at <strong>${time}</strong> on <strong>${date}</strong>.</p>
    <p style="font-size:17px">If you do not recognize this  attempt, please immediately  contact us to block the  services.</p>
    <p style="font-size:17px">Please note that PQS will never ask for any confidential information by calling from any number including its official helpline numbers, through emails or websites! Please do not share your confidential details such as  CVV, User Name, Password, OTP etc.</p>
    <p>In case of any complaint, you may contact us through:</p>
     <ul>
                    <li style="font-size:17px">Email: <a href="mailto:support@pqs.com">support@pqs.com</a></li>
                    <li style="font-size:17px">Phone: <a href="tel:+442071675747">+44 2071675747</a></li>
                    <li style="font-size:17px">Websites: <a href="https://www.pqs.com/complaint-form/">www.pqs.com/complaint-form/</a></li>
                </ul>
</div>
<div style="text-align: center; margin-top: 20px; color: #888; font-size: 13px;">
    <p>This is an automated message, please do not reply to this email.</p>
</div>
`
    };

    // Send the email
    await transporter.sendMail(mailOptions);
};



//Test controller 
const testController = (req, res) => {
    res.send("Protected Route");
};


module.exports = {
    registerController, loginController, testController, forgotPasswordController, logoutController,
    resetPasswordController,
    getAlluserController, profileUpdateController, addUserAdminController, getSingleUserController, userUpdateController
};