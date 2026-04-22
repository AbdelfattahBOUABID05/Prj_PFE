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
  template: `
    <div class="flex h-screen bg-slate-100">
      <app-sidebar></app-sidebar>

      <main class="flex-1 ml-64 overflow-auto p-8">
        <header class="flex justify-between items-center mb-8">
          <div>
            <h2 class="text-2xl font-bold text-slate-800">Gestion des Utilisateurs</h2>
            <p class="text-slate-500 text-sm">Créez, modifiez et gérez les comptes des analystes SOC</p>
          </div>
          <button (click)="openCreateModal()" 
                  class="bg-indigo-600 text-white px-6 py-2 rounded-lg hover:bg-indigo-700 transition shadow-indigo flex items-center gap-2">
            <i class="fas fa-user-plus"></i>
            Nouvel Utilisateur
          </button>
        </header>

        <!-- User Table -->
        <!-- Tableau des utilisateurs -->
        <div class="bg-white rounded-xl shadow-card overflow-hidden">
          <table class="w-full text-left border-collapse">
            <thead>
              <tr class="bg-slate-50 border-b border-slate-200">
                <th class="px-6 py-4 text-sm font-semibold text-slate-600">Utilisateur</th>
                <th class="px-6 py-4 text-sm font-semibold text-slate-600">Email</th>
                <th class="px-6 py-4 text-sm font-semibold text-slate-600">Rôle</th>
                <th class="px-6 py-4 text-sm font-semibold text-slate-600">Date Création</th>
                <th class="px-6 py-4 text-sm font-semibold text-slate-600 text-right">Actions</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-slate-100">
              <tr *ngFor="let user of users" class="hover:bg-slate-50 transition">
                <td class="px-6 py-4">
                  <div class="flex items-center gap-3">
                    <div class="w-8 h-8 rounded-full bg-indigo-100 text-indigo-600 flex items-center justify-center font-bold text-xs">
                      {{ user.username.substring(0, 2).toUpperCase() }}
                    </div>
                    <div>
                      <p class="font-medium text-slate-800">{{ user.firstName }} {{ user.lastName }}</p>
                      <p class="text-xs text-slate-500">{{ user.username }}</p>
                    </div>
                  </div>
                </td>
                <td class="px-6 py-4 text-sm text-slate-600">{{ user.email }}</td>
                <td class="px-6 py-4">
                  <span [class]="user.role === 'Admin' ? 'bg-purple-100 text-purple-700' : 'bg-blue-100 text-blue-700'"
                        class="px-2 py-1 rounded-full text-xs font-bold uppercase tracking-wider">
                    {{ user.role }}
                  </span>
                </td>
                <td class="px-6 py-4 text-sm text-slate-500">{{ user.created_at | date:'short' }}</td>
                <td class="px-6 py-4 text-right">
                  <div class="flex justify-end gap-2">
                    <button (click)="openEditModal(user)" class="p-2 text-indigo-600 hover:bg-indigo-50 rounded-lg transition" title="Modifier">
                      <i class="fas fa-edit"></i>
                    </button>
                    <button (click)="resetPassword(user)" class="p-2 text-amber-600 hover:bg-amber-50 rounded-lg transition" title="Réinitialiser MDP">
                      <i class="fas fa-key"></i>
                    </button>
                    <button (click)="deleteUser(user)" class="p-2 text-red-600 hover:bg-red-50 rounded-lg transition" title="Supprimer">
                      <i class="fas fa-trash"></i>
                    </button>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
          <div *ngIf="users.length === 0" class="p-12 text-center text-slate-400">
            <i class="fas fa-users-slash text-4xl mb-4"></i>
            <p>Aucun utilisateur trouvé.</p>
          </div>
        </div>

        <!-- Modal for Create/Edit -->
        <!-- Modal pour Création/Modification -->
        <div *ngIf="showModal" class="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/50 backdrop-blur-sm p-4">
          <div class="bg-white rounded-2xl shadow-2xl w-full max-w-md overflow-hidden">
            <div class="p-6 border-b border-slate-100 flex justify-between items-center">
              <h3 class="text-xl font-bold text-slate-800">
                {{ editingUser?.id ? 'Modifier l\\'utilisateur' : 'Nouvel Utilisateur' }}
              </h3>
              <button (click)="closeModal()" class="text-slate-400 hover:text-slate-600 transition">
                <i class="fas fa-times"></i>
              </button>
            </div>
            
            <form (ngSubmit)="saveUser()" class="p-6 space-y-4">
              <div class="grid grid-cols-2 gap-4">
                <div>
                  <label class="block text-sm font-medium text-slate-700 mb-1">Prénom</label>
                  <input type="text" [(ngModel)]="userForm.firstName" name="firstName" required
                         class="w-full px-4 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-indigo-500 outline-none">
                </div>
                <div>
                  <label class="block text-sm font-medium text-slate-700 mb-1">Nom</label>
                  <input type="text" [(ngModel)]="userForm.lastName" name="lastName" required
                         class="w-full px-4 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-indigo-500 outline-none">
                </div>
              </div>

              <div>
                <label class="block text-sm font-medium text-slate-700 mb-1">Nom d'utilisateur</label>
                <input type="text" [(ngModel)]="userForm.username" name="username" required
                       class="w-full px-4 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-indigo-500 outline-none">
              </div>

              <div>
                <label class="block text-sm font-medium text-slate-700 mb-1">Email</label>
                <input type="email" [(ngModel)]="userForm.email" name="email" required
                       class="w-full px-4 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-indigo-500 outline-none">
              </div>

              <div>
                <label class="block text-sm font-medium text-slate-700 mb-1">Rôle</label>
                <select [(ngModel)]="userForm.role" name="role" required
                        class="w-full px-4 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-indigo-500 outline-none bg-white">
                  <option value="Analyseur">Analyseur</option>
                  <option value="Admin">Administrateur</option>
                </select>
              </div>

              <div *ngIf="!editingUser?.id">
                <label class="block text-sm font-medium text-slate-700 mb-1">Mot de passe</label>
                <input type="password" [(ngModel)]="userForm.password" name="password" required
                       class="w-full px-4 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-indigo-500 outline-none">
              </div>

              <div class="pt-4 flex gap-3">
                <button type="button" (click)="closeModal()"
                        class="flex-1 px-4 py-2 border border-slate-300 rounded-lg text-slate-700 hover:bg-slate-50 transition">
                  Annuler
                </button>
                <button type="submit"
                        class="flex-1 px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition shadow-indigo">
                  {{ editingUser?.id ? 'Mettre à jour' : 'Créer' }}
                </button>
              </div>
            </form>
          </div>
        </div>
      </main>
    </div>
  `
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
