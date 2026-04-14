const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const { supabaseAdmin } = require('../config/supabase');

const generateTokens = (userId) => {
    const accessToken = jwt.sign(
        { userId },
        process.env.JWT_SECRET,
        { expiresIn: process.env.JWT_EXPIRES_IN }
    );

    const refreshToken = jwt.sign(
        { userId, type: 'refresh' },
        process.env.JWT_REFRESH_SECRET,
        { expiresIn: process.env.JWT_REFRESH_EXPIRES_IN }
    );

    return { accessToken, refreshToken };
};

const register = async (req, res) => {
    try {
        const { name, last_name, phone, email, position } = req.body;

        if (!name) {
            return res.status(400).json({ error: 'El nombre es requerido' });
        }

        const { data: existingUser } = await supabaseAdmin
            .from('users')
            .select('id')
            .eq('email', email)
            .single();

        if (existingUser) {
            return res.status(400).json({ error: 'El email ya está registrado' });
        }

        const defaultPassword = process.env.DEFAULT_PASSWORD || 'Pass123$';
        console.log('Creando usuario con contraseña por defecto:', defaultPassword);

        const { data, error } = await supabaseAdmin
            .from('users')
            .insert([{
                name,
                last_name: last_name || null,
                phone: phone || null,
                email: email || null,
                position: position || null,
                password_hash: defaultPassword,
                role: 'user',
                is_active: true
            }])
            .select();

        if (error) throw error;

        const tokens = generateTokens(data[0].id);
        const userResponse = { ...data[0] };
        delete userResponse.password_hash;

        res.status(201).json({
            message: 'Usuario creado exitosamente',
            user: userResponse,
            tokens
        });
    } catch (error) {
        console.error('Error en registro:', error);
        res.status(500).json({ error: error.message });
    }
};

const login = async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({
                error: 'Email y contraseña son requeridos'
            });
        }

        const { data: user, error } = await supabaseAdmin
            .from('users')
            .select('*')
            .eq('email', email)
            .eq('is_active', true)
            .single();

        if (error || !user) {
            return res.status(401).json({
                error: 'Credenciales inválidas'
            });
        }

        const { data: passwordCheck, error: passwordError } = await supabaseAdmin
            .rpc('check_password', {
                p_password: password,
                p_stored_hash: user.password_hash
            });

        if (passwordError || !passwordCheck) {
            return res.status(401).json({
                error: 'Credenciales inválidas'
            });
        }

        await supabaseAdmin
            .from('users')
            .update({ last_login: new Date().toISOString() })
            .eq('id', user.id);

        const tokens = generateTokens(user.id);
        const userResponse = { ...user };
        delete userResponse.password_hash;

        res.json({
            message: 'Login exitoso',
            user: userResponse,
            tokens
        });
    } catch (error) {
        console.error('Error en login:', error);
        res.status(500).json({ error: error.message });
    }
};

const refreshToken = async (req, res) => {
    try {
        const { refreshToken } = req.body;

        if (!refreshToken) {
            return res.status(400).json({ error: 'Refresh token requerido' });
        }

        const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);

        if (decoded.type !== 'refresh') {
            return res.status(401).json({ error: 'Token inválido' });
        }

        const { data: user, error } = await supabaseAdmin
            .from('users')
            .select('id')
            .eq('id', decoded.userId)
            .eq('is_active', true)
            .single();

        if (error || !user) {
            return res.status(401).json({ error: 'Usuario no encontrado' });
        }

        const tokens = generateTokens(user.id);

        res.json({ tokens });
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ error: 'Refresh token expirado' });
        }
        return res.status(401).json({ error: 'Refresh token inválido' });
    }
};

const getProfile = async (req, res) => {
    try {
        const user = req.user;

        const userResponse = { ...user };
        delete userResponse.password_hash;

        res.json(userResponse);
    } catch (error) {
        console.error('Error obteniendo perfil:', error);
        res.status(500).json({ error: error.message });
    }
};

const updateProfile = async (req, res) => {
    try {
        const userId = req.user.id;
        const updates = req.body;

        delete updates.id;
        delete updates.password_hash;
        delete updates.role;
        delete updates.is_active;
        delete updates.created_at;

        const { data, error } = await supabaseAdmin
            .from('users')
            .update(updates)
            .eq('id', userId)
            .select();

        if (error) throw error;

        const userResponse = { ...data[0] };
        delete userResponse.password_hash;

        res.json({
            message: 'Perfil actualizado exitosamente',
            user: userResponse
        });
    } catch (error) {
        console.error('Error actualizando perfil:', error);
        res.status(500).json({ error: error.message });
    }
};

const changePassword = async (req, res) => {
    try {
        const userId = req.user.id;
        const { currentPassword, newPassword } = req.body;

        if (!currentPassword || !newPassword) {
            return res.status(400).json({
                error: 'Contraseña actual y nueva contraseña son requeridas'
            });
        }

        const { data: user, error: fetchError } = await supabaseAdmin
            .from('users')
            .select('password_hash')
            .eq('id', userId)
            .single();

        if (fetchError) throw fetchError;

        const { data: passwordCheck, error: passwordError } = await supabaseAdmin
            .rpc('check_password', {
                p_password: currentPassword,
                p_stored_hash: user.password_hash
            });

        if (passwordError || !passwordCheck) {
            return res.status(401).json({
                error: 'Contraseña actual incorrecta'
            });
        }

        const { error: updateError } = await supabaseAdmin
            .from('users')
            .update({ password_hash: newPassword })
            .eq('id', userId);

        if (updateError) throw updateError;

        res.json({ message: 'Contraseña cambiada exitosamente' });
    } catch (error) {
        console.error('Error cambiando contraseña:', error);
        res.status(500).json({ error: error.message });
    }
};

const logout = async (req, res) => {
    res.json({ message: 'Logout exitoso' });
};

const createEmailTransporter = () => {
    return nodemailer.createTransport({
        host: 'live.smtp.mailtrap.io',
        port: 587,
        auth: {
            user: 'api',
            pass: process.env.MAILTRAP_TOKEN
        }
    });
};

const requestPasswordReset = async (req, res) => {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({ error: 'El email es requerido' });
        }

        const { data: user, error: userError } = await supabaseAdmin
            .from('users')
            .select('id, name, email')
            .eq('email', email)
            .eq('is_active', true)
            .single();

        if (userError || !user) {
            return res.status(404).json({ error: 'Usuario no encontrado' });
        }

        if (!user.id) {
            return res.status(400).json({ error: 'ID de usuario inválido' });
        }

        const resetToken = jwt.sign(
            { userId: user.id, type: 'password_reset' },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );

        const expiresAt = new Date(Date.now() + (60 * 60 * 1000)).toISOString();

        const { error: storeError } = await supabaseAdmin
            .from('password_reset_tokens')
            .insert([{
                user_id: user.id,
                token: resetToken,
                expires_at: expiresAt
            }]);

        if (storeError) {
            console.error('Error almacenando token:', storeError);
            throw storeError;
        }

        const resetLink = `${process.env.FRONTEND_URL}/#/reset-password?token=${resetToken}`;

        console.log('Link de reset:', resetLink);

        const client = createEmailTransporter();
        
        try {
            await client.sendMail({
                from: 'hello@demomailtrap.co',
                to: user.email,
                subject: 'Recupera tu contraseña - Task Management',
                html: `
                    <h2>¡Hola ${user.name}!</h2>
                    <p>Recibimos una solicitud para recuperar tu contraseña.</p>
                    <p>Haz clic en el siguiente enlace para restablecer tu contraseña:</p>
                    <a href="${resetLink}" style="background-color: #3b82f6; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block;">
                        Restablecer Contraseña
                    </a>
                    <p>O copia y pega este enlace en tu navegador:</p>
                    <p>${resetLink}</p>
                    <p>Este enlace expirará en 1 hora.</p>
                    <p>Si no solicitaste este cambio, ignora este correo.</p>
                `
            });
            console.log('Email enviado exitosamente a:', user.email);
        } catch (emailError) {
            console.error('Error enviando email:', emailError.message);
        }

        res.json({ 
            message: 'Se ha enviado un enlace de recuperación a tu correo electrónico'
        });
    } catch (error) {
        console.error('Error solicitando recuperación de contraseña:', error);
        res.status(500).json({ error: error.message || 'Error al solicitar recuperación de contraseña' });
    }
};

const resetPassword = async (req, res) => {
    try {
        const { token, newPassword } = req.body;

        if (!token || !newPassword) {
            return res.status(400).json({ error: 'Token y nueva contraseña son requeridos' });
        }

        let decoded;
        try {
            decoded = jwt.verify(token, process.env.JWT_SECRET);
        } catch (error) {
            return res.status(401).json({ error: 'Token inválido o expirado' });
        }

        if (decoded.type !== 'password_reset') {
            return res.status(401).json({ error: 'Token inválido' });
        }

        const { data: tokenRecord, error: tokenError } = await supabaseAdmin
            .from('password_reset_tokens')
            .select('*')
            .eq('token', token)
            .single();

        if (tokenError || !tokenRecord) {
            return res.status(401).json({ error: 'Token no encontrado o ya fue utilizado' });
        }

        if (new Date(tokenRecord.expires_at) < new Date()) {
            return res.status(401).json({ error: 'Token expirado' });
        }

        const { error: updateError } = await supabaseAdmin
            .from('users')
            .update({ password_hash: newPassword })
            .eq('id', decoded.userId);

        if (updateError) throw updateError;

        const { error: deleteError } = await supabaseAdmin
            .from('password_reset_tokens')
            .delete()
            .eq('id', tokenRecord.id);

        if (deleteError) throw deleteError;

        res.json({ message: 'Contraseña restablecida exitosamente' });
    } catch (error) {
        console.error('Error restableciendo contraseña:', error);
        res.status(500).json({ error: 'Error al restablecer la contraseña' });
    }
};

module.exports = {
    register,
    login,
    refreshToken,
    getProfile,
    updateProfile,
    changePassword,
    requestPasswordReset,
    resetPassword,
    logout
};