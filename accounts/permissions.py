from rest_framework import permissions


class IsAdmin(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.role == request.user.Roles.ADMIN


class IsSOCLeadOrAbove(permissions.BasePermission):
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        return request.user.role in {request.user.Roles.ADMIN, request.user.Roles.SOC_LEAD}


class ReadOnlyOrSOCAnalyst(permissions.BasePermission):
    SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        if request.method in self.SAFE_METHODS:
            return True
        return request.user.role in {
            request.user.Roles.ADMIN,
            request.user.Roles.SOC_LEAD,
            request.user.Roles.SOC_ANALYST,
        }
