let express = require('express');
let router = express.Router()
let userController = require('../controllers/users')
let bcrypt = require('bcrypt')
let { generateToken, requireLogin } = require('../utils/authHandler')
let { validatedResult, ChangePasswordValidator } = require('../utils/validator')

// POST /api/v1/auth/register
router.post('/register', async function (req, res, next) {
    try {
        let { username, password, email } = req.body;
        let newUser = await userController.CreateAnUser(username, password, email,
            "69b1265c33c5468d1c85aad8"
        )
        res.send(newUser)
    } catch (error) {
        res.status(400).json({
            message: error.message
        })
    }
})

// POST /api/v1/auth/login
router.post('/login', async function (req, res, next) {
    try {
        let { username, password } = req.body;
        let user = await userController.GetAnUserByUsername(username);
        if (!user) {
            return res.status(401).json({ message: "Thông tin đăng nhập không đúng" });
        }
        if (user.lockTime > Date.now()) {
            return res.status(403).json({ message: "Tài khoản đang bị khóa, vui lòng thử lại sau" });
        }
        if (bcrypt.compareSync(password, user.password)) {
            // Reset loginCount khi đăng nhập thành công
            user.loginCount = 0;
            await user.save()

            // Tạo JWT RS256 token
            const token = generateToken({
                _id: user._id,
                username: user.username,
                role: user.role
            }, '1h')

            res.json({
                message: "Đăng nhập thành công",
                token: token
            })
        } else {
            user.loginCount++;
            if (user.loginCount == 3) {
                user.loginCount = 0;
                user.lockTime = Date.now() + 3600 * 1000; // Khóa 1 giờ
            }
            await user.save()
            res.status(401).json({ message: "Thông tin đăng nhập không đúng" })
        }
    } catch (error) {
        res.status(500).json({ message: error.message })
    }
})

// POST /api/v1/auth/changepassword  (yêu cầu đăng nhập)
router.post('/changepassword',
    requireLogin,                   // 1. Kiểm tra JWT
    ChangePasswordValidator,        // 2. Validate body
    validatedResult,                // 3. Trả lỗi nếu validate thất bại
    async function (req, res, next) {
        try {
            let { oldPassword, newPassword } = req.body;
            let userId = req.user._id; // Lấy từ JWT đã decode

            await userController.ChangePassword(userId, oldPassword, newPassword);

            res.json({ message: "Đổi mật khẩu thành công" });
        } catch (error) {
            res.status(400).json({ message: error.message })
        }
    })

// GET /api/v1/auth/me  (yêu cầu đăng nhập)
router.get('/me',
    requireLogin,
    async function (req, res, next) {
        try {
            let user = await userController.GetUserById(req.user._id);
            if (!user) {
                return res.status(404).json({ message: "Không tìm thấy người dùng" });
            }
            // Trả về thông tin user, loại bỏ password
            let { password, ...userInfo } = user.toObject();
            res.json(userInfo);
        } catch (error) {
            res.status(500).json({ message: error.message });
        }
    })

module.exports = router