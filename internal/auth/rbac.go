package auth

// CheckPermission verifies the user has the required role.
func CheckPermission(userRoles []string, required string) bool {
    for _, role := range userRoles {
        if role == required || role == "admin" {
            return true
        }
    }
    return false
}

