import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { RouterModule } from '@angular/router';
import { HttpClient } from '@angular/common/http';
import { environment } from '../../../environments/environment';
import { LogService, SettingsPayload } from '../../services/log.service';
import { SidebarComponent } from '../sidebar/sidebar.component';

@Component({
  selector: 'app-settings',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterModule, SidebarComponent],
  template: `
    <div class="flex h-screen bg-slate-100">
      <app-sidebar></app-sidebar>

      <!-- Main Content -->
      <main class="flex-1 ml-64 overflow-auto p-8">
        <div class="max-w-2xl mx-auto space-y-6">
          <header class="mb-8">
            <h2 class="text-2xl font-bold text-slate-800">Paramètres</h2>
            <p class="text-slate-500 text-sm">Configurez vos préférences de notification et SMTP</p>
          </header>

          <!-- Email Notifications -->
          <div class="bg-white rounded-xl shadow-card p-6">
            <h3 class="text-lg font-bold text-slate-800 mb-4">
              <i class="fas fa-envelope text-indigo-600 mr-2"></i>
              Notifications Email
            </h3>

            <div class="space-y-4">
              <div class="flex items-center">
                <input type="checkbox" id="emailNotif" [(ngModel)]="settings.emailNotifications"
                       class="w-4 h-4 text-indigo-600 rounded focus:ring-indigo-500">
                <label for="emailNotif" class="ml-2 text-sm text-slate-700">
                  Activer les notifications par email
                </label>
              </div>

              <div>
                <label class="block text-sm font-medium text-slate-700 mb-1">Email de notification</label>
                <input type="email" [(ngModel)]="settings.notificationEmail"
                       class="w-full px-4 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-indigo-500"
                       placeholder="notif@exemple.com">
              </div>
            </div>
          </div>

          <!-- SMTP Configuration -->
          <div class="bg-white rounded-xl shadow-card p-6">
            <h3 class="text-lg font-bold text-slate-800 mb-4">
              <i class="fas fa-server text-indigo-600 mr-2"></i>
              Configuration SMTP
            </h3>

            <div class="space-y-4">
              <div>
                <label class="block text-sm font-medium text-slate-700 mb-1">Serveur SMTP</label>
                <input type="text" [(ngModel)]="settings.smtpServer"
                       class="w-full px-4 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-indigo-500"
                       placeholder="smtp.gmail.com">
              </div>

              <div>
                <label class="block text-sm font-medium text-slate-700 mb-1">Port SMTP</label>
                <input type="number" [(ngModel)]="settings.smtpPort"
                       class="w-full px-4 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-indigo-500"
                       placeholder="587">
              </div>

              <div>
                <label class="block text-sm font-medium text-slate-700 mb-1">Utilisateur SMTP</label>
                <input type="text" [(ngModel)]="settings.smtpUser"
                       class="w-full px-4 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-indigo-500"
                       placeholder="votre-email@gmail.com">
              </div>

              <div>
                <label class="block text-sm font-medium text-slate-700 mb-1">Mot de passe SMTP</label>
                <input type="password" [(ngModel)]="settings.smtpPassword"
                       class="w-full px-4 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-indigo-500"
                       placeholder="App Password">
              </div>
            </div>
          </div>

          <button (click)="saveSettings()"
                  class="w-full bg-indigo-600 hover:bg-indigo-700 text-white font-semibold py-3 rounded-lg transition">
            <i class="fas fa-save mr-2"></i>
            Enregistrer les paramètres
          </button>

          <!-- Signature Management -->
          <div class="bg-white rounded-xl shadow-card p-6 mt-6">
            <h3 class="text-lg font-bold text-slate-800 mb-4">
              <i class="fas fa-pen-nib text-indigo-600 mr-2"></i>
              Signature de l'Analyste
            </h3>

            <div class="space-y-6 text-center">
              <div class="relative w-full h-48 bg-slate-50 border-2 border-dashed border-slate-200 rounded-xl flex items-center justify-center overflow-hidden">
                <img *ngIf="signaturePreview" [src]="signaturePreview" class="h-full object-contain filter contrast-125">
                <div *ngIf="!signaturePreview" class="text-slate-300 italic text-sm">
                  Aucune signature enregistrée
                </div>
              </div>

              <div class="flex gap-4 justify-center">
                <input #sigInput type="file" (change)="onSignatureSelected($event)" accept="image/*" class="hidden">
                <button (click)="sigInput.click()" class="bg-slate-100 hover:bg-slate-200 text-slate-700 px-4 py-2 rounded-lg text-sm font-bold transition flex items-center gap-2">
                  <i class="fas fa-upload"></i> Charger une image
                </button>
                <button (click)="uploadSignature()" [disabled]="!selectedSignature" class="bg-indigo-600 hover:bg-indigo-700 text-white px-4 py-2 rounded-lg text-sm font-bold transition disabled:opacity-50 flex items-center gap-2">
                  <i class="fas fa-check"></i> Valider la signature
                </button>
              </div>
              <p class="text-[10px] text-slate-400 uppercase font-bold tracking-widest">
                Conseil : Utilisez un fond blanc. Le système supprimera automatiquement l'arrière-plan via Remove.bg.
              </p>
            </div>
          </div>
        </div>
      </main>
    </div>
  `
})
export class SettingsComponent implements OnInit {
  settings: SettingsPayload = {
    emailNotifications: false,
    notificationEmail: '',
    smtpServer: 'smtp.gmail.com',
    smtpPort: 587,
    smtpUser: '',
    smtpPassword: ''
  };

  selectedSignature: File | null = null;
  signaturePreview: string | null = null;

  constructor(private logService: LogService, private http: HttpClient) {}

  ngOnInit(): void {
    this.loadSettings();
    this.loadProfile();
  }

  loadSettings(): void {
    this.logService.getSettings().subscribe({
      next: (response: any) => {
        if (response.status === 'success' && response.settings) {
          this.settings = {
            ...response.settings,
            smtpPassword: ''
          };
        }
      },
      error: (err: any) => console.error('Settings load error:', err)
    });
  }

  loadProfile(): void {
    const apiUrl = environment.apiUrl;
    this.http.get<any>(`${apiUrl}/profile`).subscribe({
      next: (res: any) => {
        if (res.signature_path) {
          this.signaturePreview = `${apiUrl}/static/${res.signature_path}`;
        }
      },
      error: (err: any) => console.error('Profile load error:', err)
    });
  }

  onSignatureSelected(event: any): void {
    const file = event.target.files[0];
    if (file) {
      this.selectedSignature = file;
      const reader = new FileReader();
      reader.onload = (e: any) => this.signaturePreview = e.target.result;
      reader.readAsDataURL(file);
    }
  }

  uploadSignature(): void {
    if (!this.selectedSignature) return;

    const formData = new FormData();
    formData.append('signature', this.selectedSignature);

    const apiUrl = environment.apiUrl;
    this.http.post<any>(`${apiUrl}/profile/upload-signature`, formData).subscribe({
      next: (res: any) => {
        alert('Signature mise à jour avec succès !');
        if (res.signature_path) {
          this.signaturePreview = `${apiUrl}/static/${res.signature_path}`;
        }
        this.selectedSignature = null;
      },
      error: (err: any) => alert('Erreur lors de l\'upload de la signature.')
    });
  }

  saveSettings(): void {
    this.logService.saveSettings(this.settings).subscribe({
      next: (response: any) => alert(response.message || 'Paramètres enregistrés avec succès !'),
      error: (err: any) => {
        const message = err?.error?.message || 'Erreur lors de la sauvegarde des paramètres';
        alert(message);
      }
    });
  }
}
