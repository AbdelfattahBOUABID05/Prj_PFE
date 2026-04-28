import { HttpInterceptorFn, HttpRequest, HttpHandlerFn, HttpEvent, HttpErrorResponse } from '@angular/common/http';
import { inject } from '@angular/core';
import { Router } from '@angular/router';
import { Observable, throwError } from 'rxjs';
import { catchError } from 'rxjs/operators';

/**
 * Intercepteur d'authentification moderne (Angular 17+)
 * Ajoute le token Bearer JWT à toutes les requêtes HTTP sortantes
 * Gère également les erreurs d'authentification (401)
 */
export const authInterceptor: HttpInterceptorFn = (req: HttpRequest<unknown>, next: HttpHandlerFn): Observable<HttpEvent<unknown>> => {
  const router = inject(Router);
  
  // Récupération du token depuis le localStorage
  const token = localStorage.getItem('token');

  let authReq = req;

  // Si un token est présent, on clone la requête pour y ajouter le header Authorization
  if (token && token.trim() !== '') {
    authReq = req.clone({
      setHeaders: {
        Authorization: `Bearer ${token}`
      }
    });
  }

  // On passe la requête modifiée au gestionnaire suivant et on gère les erreurs
  return next(authReq).pipe(
    catchError((error: HttpErrorResponse) => {
      // Si on reçoit une erreur 401 (Unauthorized), on redirige vers le login
      if (error.status === 401) {
        console.warn('Session expirée ou non autorisée, redirection vers la page de connexion');
        
        // On ne nettoie pas forcément tout de suite pour laisser le service d'auth le faire
        // ou on peut le faire ici par sécurité
        // localStorage.removeItem('token');
        
        // Redirection vers login
        router.navigate(['/login'], { 
          queryParams: { returnUrl: router.url, error: 'session_expired' } 
        });
      }
      
      return throwError(() => error);
    })
  );
};
