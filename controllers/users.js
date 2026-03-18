let userModel = require('../schemas/users')
let bcrypt = require('bcrypt')

module.exports = {
    CreateAnUser: async function (username, password, email, role,
        fullName, avatarUrl, status, loginCount) {
        let newItem = new userModel({
            username: username,
            password: password,
            email: email,
            fullName: fullName,
            avatarUrl: avatarUrl,
            status: status,
            role: role,
            loginCount: loginCount
        });
        await newItem.save();
        return newItem;
    },
    GetAnUserByUsername: async function (username) {
        return await userModel.findOne({
            isDeleted: false,
            username: username
        })
    },
    GetUserById: async function (id) {
        return await userModel.findOne({
            _id: id,
            isDeleted: false
        })
    },
    ChangePassword: async function (userId, oldPassword, newPassword) {
        let user = await userModel.findOne({ _id: userId, isDeleted: false });
        if (!user) {
            throw new Error("Người dùng không tồn tại");
        }
        // Kiểm tra oldPassword có khớp không
        let isMatch = bcrypt.compareSync(oldPassword, user.password);
        if (!isMatch) {
            throw new Error("Mật khẩu cũ không đúng");
        }
        // Gán password mới → pre('save') hook sẽ tự hash
        user.password = newPassword;
        await user.save();
        return true;
    }
}