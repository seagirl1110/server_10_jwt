const authorizeRole = (role) => {
  return (req, res, next) => {
    if (req.user.role === role) {
      next();
    } else {
      return res.status(403).json({
        message: "Forbidden: You don't have access to this resource.",
      });
    }
  };
};

export default authorizeRole;
