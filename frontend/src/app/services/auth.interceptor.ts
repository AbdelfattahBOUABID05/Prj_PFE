import { HttpInterceptorFn, HttpRequest, HttpHandlerFn, HttpEvent } from '@angular/common/http';
import { Observable } from 'rxjs';

/**
 * Intercepteur d'authentification moderne (Angular 17+)
 * Ajoute le token Bearer JWT à toutes les requêtes HTTP sortantes
 */
export const authInterceptor: HttpInterceptorFn = (req: HttpRequest<unknown>, next: HttpHandlerFn): Observable<HttpEvent<unknown>> => {
  // Récupération du token depuis le localStorage
  const token = localStorage.getItem('token');

  // Si un token est présent, on clone la requête pour y ajouter le header Authorization
  if (token && token.trim() !== '') {
    const authReq = req.clone({
      setHeaders: {
        Authorization: `Bearer ${token}`
      }
    });
    return next(authReq);
  }

  // Sinon, on laisse passer la requête originale
  return next(req);
};
