function authorizeRoles(...allowedRoles) {
  return (req, res, next) => {
    const roleMap = {1: 'Admin', 2: 'Manager', 3: 'Viewer'};
    const userRole = roleMap[req.user.role_id];
    
    if (!allowedRoles.includes(userRole)) {
      return res.status(403).json({ error: `Access denied. Required: ${allowedRoles.join(', ')}` });
    }
    next();
  };
}

module.exports = authorizeRoles;
