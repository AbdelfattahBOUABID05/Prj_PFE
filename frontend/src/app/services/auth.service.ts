import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, tap } from 'rxjs';
import { environment } from '../../environments/environment';

export interface LoginPayload {
  username: string;
  password: string;
}

export interface AuthResponse {
  status: string;
  message: string;
  token?: string;
  username?: string;
  role?: string;
  firstName?: string;
  lastName?: string;
}

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private apiUrl = environment.apiUrl;

  constructor(private http: HttpClient) {}

  login(payload: LoginPayload): Observable<AuthResponse> {
    return this.http.post<AuthResponse>(`${this.apiUrl}/login`, payload).pipe(
      tap(res => {
        if (res.status === 'success' && res.token) {
          this.saveSession(res);
        }
      })
    );
  }

  private saveSession(res: AuthResponse): void {
    if (res.token) {
      // Clear any existing session data before saving new session
      localStorage.clear();
      
      localStorage.setItem('token', res.token);
      if (res.username) localStorage.setItem('username', res.username);
      if (res.role) localStorage.setItem('role', res.role);
      if (res.firstName) localStorage.setItem('firstName', res.firstName);
      if (res.lastName) localStorage.setItem('lastName', res.lastName);
    }
  }

  logout(): Observable<AuthResponse> {
    const token = this.getToken();
    localStorage.clear();
    // Use the stored token to authorize the logout request if needed, 
    // but typically we just clear the local state.
    return this.http.post<AuthResponse>(`${this.apiUrl}/logout`, {});
  }

  getToken(): string | null {
    return localStorage.getItem('token');
  }

  getRole(): string | null {
    return localStorage.getItem('role');
  }

  isAdmin(): boolean {
    const role = this.getRole()?.toLowerCase();
    return role === 'admin';
  }

  isLoggedIn(): boolean {
    const token = this.getToken();
    return token !== null && token !== '';
  }
}