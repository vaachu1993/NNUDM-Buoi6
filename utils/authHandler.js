const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

// Đọc RSA keys một lần khi khởi động
const privateKey = fs.readFileSync(path.join(__dirname, '../keys/private.pem'));
const publicKey = fs.readFileSync(path.join(__dirname, '../keys/public.pem'));

module.exports = {
    /**
     * Tạo JWT token bằng thuật toán RS256
     * @param {object} payload - dữ liệu muốn đưa vào token
     * @param {string} expiresIn - thời gian hết hạn (vd: '1h', '7d')
     */
    generateToken: function (payload, expiresIn = '1h') {
        return jwt.sign(payload, privateKey, {
            algorithm: 'RS256',
            expiresIn: expiresIn
        });
    },

    /**
     * Verify token và giải mã payload
     * @param {string} token
     */
    verifyToken: function (token) {
        return jwt.verify(token, publicKey, { algorithms: ['RS256'] });
    },

    /**
     * Middleware: Yêu cầu đăng nhập (xác thực JWT)
     * Lấy token từ header: Authorization: Bearer <token>
     */
    requireLogin: function (req, res, next) {
        const authHeader = req.headers['authorization'];
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ message: 'Bạn chưa đăng nhập' });
        }

        const token = authHeader.split(' ')[1];
        try {
            const decoded = jwt.verify(token, publicKey, { algorithms: ['RS256'] });
            req.user = decoded; // Gắn thông tin user vào request
            next();
        } catch (err) {
            if (err.name === 'TokenExpiredError') {
                return res.status(401).json({ message: 'Token đã hết hạn, vui lòng đăng nhập lại' });
            }
            return res.status(401).json({ message: 'Token không hợp lệ' });
        }
    }
};
