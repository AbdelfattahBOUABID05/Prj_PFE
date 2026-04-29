import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { HttpClient } from '@angular/common/http';
import { SidebarComponent } from '../../sidebar/sidebar.component';
import { environment } from '../../../../environments/environment';

interface User {
  id?: number;
  username: string;
  email: string;
  firstName: string;
  lastName: string;
  role: string;
  password?: string;
  created_at?: string;
}

@Component({
  selector: 'app-user-management',
  standalone: true,
  imports: [CommonModule, FormsModule, SidebarComponent],
  templateUrl: './user-management.component.html',
  styleUrls: ['./user-management.component.css']
})
export class UserManagementComponent implements OnInit {
  users: User[] = [];
  showModal = false;
  editingUser: User | null = null;
  userForm: User = { username: '', email: '', firstName: '', lastName: '', role: 'Analyseur', password: '' };
  private apiUrl = environment.apiUrl;

  constructor(private http: HttpClient) {}

  ngOnInit(): void {
    this.fetchUsers();
  }

  fetchUsers(): void {
    this.http.get<{ status: string; users: User[] }>(`${this.apiUrl}/admin/users`).subscribe({
      next: (res) => this.users = res.users,
      error: (err) => console.error('Error fetching users:', err)
    });
  }

  openCreateModal(): void {
    this.editingUser = null;
    this.userForm = { username: '', email: '', firstName: '', lastName: '', role: 'Analyseur', password: '' };
    this.showModal = true;
  }

  openEditModal(user: User): void {
    this.editingUser = { ...user };
    this.userForm = { ...user };
    this.showModal = true;
  }

  closeModal(): void {
    this.showModal = false;
  }

  saveUser(): void {
    if (this.editingUser?.id) {
      // Update
      this.http.put(`${this.apiUrl}/admin/users/${this.editingUser.id}`, this.userForm).subscribe({
        next: () => {
          this.fetchUsers();
          this.closeModal();
        },
        error: (err) => alert(err.error?.message || 'Erreur lors de la mise à jour')
      });
    } else {
      // Create
      this.http.post(`${this.apiUrl}/admin/users`, this.userForm).subscribe({
        next: () => {
          this.fetchUsers();
          this.closeModal();
        },
        error: (err) => alert(err.error?.message || 'Erreur lors de la création')
      });
    }
  }

  deleteUser(user: User): void {
    if (confirm(`Êtes-vous sûr de vouloir supprimer l\\'utilisateur ${user.username} ?`)) {
      this.http.delete(`${this.apiUrl}/admin/users/${user.id}`).subscribe({
        next: () => this.fetchUsers(),
        error: (err) => alert(err.error?.message || 'Erreur lors de la suppression')
      });
    }
  }

  resetPassword(user: User): void {
    const newPass = prompt(`Entrez le nouveau mot de passe pour ${user.username} :`);
    if (newPass) {
      this.http.put(`${this.apiUrl}/admin/users/${user.id}`, { password: newPass }).subscribe({
        next: () => alert('Mot de passe réinitialisé avec succès'),
        error: (err) => alert(err.error?.message || 'Erreur lors de la réinitialisation')
      });
    }
  }
}
