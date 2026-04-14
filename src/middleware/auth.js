const jwt = require('jsonwebtoken');
const { supabaseAdmin } = require('../config/supabase');

const verifyToken = async (req, res, next) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];

        if (!token) {
            return res.status(401).json({
                error: 'Acceso denegado. No se proporcionó token.'
            });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        const { data: user, error } = await supabaseAdmin
            .from('users')
            .select('*')
            .eq('id', decoded.userId)
            .eq('is_active', true)
            .single();

        if (error || !user) {
            return res.status(401).json({
                error: 'Usuario no encontrado o inactivo'
            });
        }

        req.user = user;
        next();
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({
                error: 'Token expirado'
            });
        }
        return res.status(401).json({
            error: 'Token inválido'
        });
    }
};

const authorize = (...roles) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({ error: 'Usuario no autenticado' });
        }

        if (!roles.includes(req.user.role)) {
            console.warn(`Usuario ${req.user.email} con rol ${req.user.role} no tiene permisos para acceder a esta ruta. Roles requeridos: ${roles.join(', ')}`);   
            return res.status(403).json({
                error: 'No tienes permisos para realizar esta acción'
            });
        }

        next();
    };
};

module.exports = { verifyToken, authorize };