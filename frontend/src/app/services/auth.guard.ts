import { inject } from '@angular/core';
import { Router, CanActivateFn, ActivatedRouteSnapshot, RouterStateSnapshot } from '@angular/router';
import { AuthService } from './auth.service';

/**
 * Guard to protect routes based on authentication and roles
 * Guard pour protéger les routes selon l'authentification et les rôles
 */
export const authGuard: CanActivateFn = (route: ActivatedRouteSnapshot, state: RouterStateSnapshot) => {
  const authService = inject(AuthService);
  const router = inject(Router);

  // Check if user is logged in
  // Vérifier si l'utilisateur est connecté
  if (!authService.isLoggedIn()) {
    router.navigate(['/login']);
    return false;
  }

  // Check if route has role restrictions
  // Vérifier si la route a des restrictions de rôle
  const expectedRole = route.data['role'];
  if (expectedRole) {
    const userRole = authService.getRole();
    if (userRole !== expectedRole) {
      // If user is Admin, they can access Analyst routes, but not vice-versa
      // Si l'utilisateur est Admin, il peut accéder aux routes Analyst, mais pas l'inverse
      if (userRole === 'Admin') {
        return true;
      }
      
      // Redirect to dashboard if role doesn't match
      // Rediriger vers le tableau de bord si le rôle ne correspond pas
      router.navigate(['/dashboard']);
      return false;
    }
  }

  return true;
};
