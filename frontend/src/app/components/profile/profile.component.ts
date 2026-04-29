import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { HttpClient } from '@angular/common/http';
import { SidebarComponent } from '../sidebar/sidebar.component';
import { environment } from '../../../environments/environment';
import { AuthService } from '../../services/auth.service';

@Component({
  selector: 'app-profile',
  standalone: true,
  imports: [CommonModule, FormsModule, SidebarComponent],
  templateUrl: './profile.component.html',
  styleUrls: ['./profile.component.css']
})
export class ProfileComponent implements OnInit {
  username = '';
  fullName = '';
  firstName = '';
  lastName = '';
  roleLabel = '';
  email = '';
  
  passwords = { old: '', new: '', confirm: '' };
  loadingPass = false;
  qrCodeBase64: string | null = null;

  private apiUrl = environment.apiUrl;

  constructor(private http: HttpClient, private authService: AuthService) {}

  ngOnInit(): void {
    this.loadUserData();
    this.loadQRCode();
  }

  isFirstLogin(): boolean {
    return this.authService.isFirstLogin();
  }

  loadQRCode(): void {
    this.http.get<any>(`${this.apiUrl}/generate-qr`).subscribe({
      next: (res) => {
        if (res.status === 'success') {
          this.qrCodeBase64 = res.qr_code;
        }
      },
      error: (err) => console.error('Erreur chargement QR Code:', err)
    });
  }

  loadUserData(): void {
    this.username = localStorage.getItem('username') || '';
    this.firstName = localStorage.getItem('firstName') || '';
    this.lastName = localStorage.getItem('lastName') || '';
    this.fullName = `${this.firstName} ${this.lastName}`.trim() || this.username;
    this.roleLabel = localStorage.getItem('role') === 'Admin' ? 'Administrateur' : 'Analyseur';
    
    this.http.get<any>(`${this.apiUrl}/profile`).subscribe({
      next: (res) => {
        this.email = res.email;
        this.firstName = res.firstName || this.firstName;
        this.lastName = res.lastName || this.lastName;
        this.fullName = `${this.firstName} ${this.lastName}`.trim() || this.username;
      }
    });
  }

  changePassword(): void {
    if (this.passwords.new !== this.passwords.confirm) {
      alert('Les nouveaux mots de passe ne correspondent pas.');
      return;
    }
    this.loadingPass = true;
    this.http.post(`${this.apiUrl}/profile/change-password`, this.passwords).subscribe({
      next: () => {
        alert('Mot de passe mis à jour avec succès !');
        this.authService.updateFirstLoginStatus(false);
        this.passwords = { old: '', new: '', confirm: '' };
        this.loadingPass = false;
      },
      error: (err) => {
        alert(err.error?.message || 'Erreur lors de la mise à jour');
        this.loadingPass = false;
      }
    });
  }
}
