import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { HttpClient } from '@angular/common/http';
import { SidebarComponent } from '../sidebar/sidebar.component';
import { environment } from '../../../environments/environment';

@Component({
  selector: 'app-profile',
  standalone: true,
  imports: [CommonModule, FormsModule, SidebarComponent],
  template: `
    <div class="flex h-screen bg-slate-100">
      <app-sidebar></app-sidebar>

      <main class="flex-1 ml-64 overflow-auto p-8">
        <div class="max-w-4xl mx-auto space-y-8">
          <header>
            <h2 class="text-3xl font-bold text-slate-800">Mon Profil</h2>
            <p class="text-slate-500">Gérez vos informations personnelles et votre signature d\\'expert</p>
          </header>

          <div class="grid grid-cols-3 gap-8">
            <!-- Password Change Section -->
            <!-- Section changement de mot de passe -->
            <div class="col-span-1 space-y-6">
              <div class="bg-white rounded-2xl shadow-card p-6 border border-slate-200">
                <h3 class="text-lg font-bold text-slate-800 mb-6 flex items-center gap-2">
                  <i class="fas fa-key text-indigo-600"></i>
                  Sécurité
                </h3>
                
                <form (ngSubmit)="changePassword()" class="space-y-4">
                  <div>
                    <label class="block text-xs font-bold text-slate-500 uppercase mb-2">Ancien mot de passe</label>
                    <input type="password" [(ngModel)]="passwords.old" name="old" required
                           class="w-full px-4 py-2 bg-slate-50 border border-slate-200 rounded-lg focus:ring-2 focus:ring-indigo-500 outline-none">
                  </div>
                  <div>
                    <label class="block text-xs font-bold text-slate-500 uppercase mb-2">Nouveau mot de passe</label>
                    <input type="password" [(ngModel)]="passwords.new" name="new" required
                           class="w-full px-4 py-2 bg-slate-50 border border-slate-200 rounded-lg focus:ring-2 focus:ring-indigo-500 outline-none">
                  </div>
                  <div>
                    <label class="block text-xs font-bold text-slate-500 uppercase mb-2">Confirmer nouveau</label>
                    <input type="password" [(ngModel)]="passwords.confirm" name="confirm" required
                           class="w-full px-4 py-2 bg-slate-50 border border-slate-200 rounded-lg focus:ring-2 focus:ring-indigo-500 outline-none">
                  </div>
                  <button type="submit" [disabled]="loadingPass"
                          class="w-full bg-slate-800 hover:bg-slate-900 text-white font-bold py-3 rounded-lg transition text-sm disabled:opacity-50">
                    {{ loadingPass ? 'Mise à jour...' : 'Modifier le mot de passe' }}
                  </button>
                </form>
              </div>
            </div>

            <!-- Signature Section -->
            <!-- Section signature -->
            <div class="col-span-2 space-y-6">
              <div class="bg-white rounded-2xl shadow-card p-8 border border-slate-200">
                <div class="flex justify-between items-center mb-8">
                  <h3 class="text-lg font-bold text-slate-800 flex items-center gap-2">
                    <i class="fas fa-pen-nib text-indigo-600"></i>
                    Signature d\\'Expert SOC
                  </h3>
                  <span class="px-3 py-1 bg-indigo-50 text-indigo-600 text-[10px] font-bold uppercase tracking-wider rounded-full border border-indigo-100">
                    Propulsé par Remove.bg
                  </span>
                </div>

                <div class="grid grid-cols-2 gap-8">
                  <div class="space-y-4">
                    <div class="border-2 border-dashed border-slate-200 rounded-2xl p-8 text-center hover:border-indigo-400 transition cursor-pointer bg-slate-50"
                         (click)="sigInput.click()">
                      <input #sigInput type="file" (change)="onSignatureSelected($event)" accept="image/*" class="hidden">
                      <i class="fas fa-cloud-upload-alt text-4xl text-slate-300 mb-4"></i>
                      <p class="text-sm font-bold text-slate-600">Cliquez pour télécharger votre signature</p>
                      <p class="text-xs text-slate-400 mt-2">Format PNG, JPG recommandé</p>
                    </div>
                    <p class="text-[10px] text-slate-400 leading-relaxed italic">
                      Note: L\\'arrière-plan sera automatiquement supprimé pour un rendu professionnel dans vos rapports d\\'analyse.
                    </p>
                  </div>

                  <div class="flex flex-col items-center justify-center p-6 bg-slate-50 rounded-2xl border border-slate-100 min-h-[200px]">
                    <p class="text-xs font-bold text-slate-400 uppercase mb-4">Aperçu de la signature</p>
                    <div class="w-full h-32 flex items-center justify-center">
                      <img *ngIf="signaturePreview" [src]="signaturePreview" class="max-w-full max-h-full object-contain">
                      <div *ngIf="!signaturePreview" class="text-slate-300 italic text-sm">Aucune signature</div>
                    </div>
                    <button *ngIf="selectedFile" (click)="uploadSignature()" [disabled]="loadingSig"
                            class="mt-6 px-6 py-2 bg-indigo-600 text-white font-bold rounded-lg hover:bg-indigo-700 transition shadow-indigo text-sm flex items-center gap-2">
                      <i class="fas" [class.fa-magic]="!loadingSig" [class.fa-spinner]="loadingSig" [class.fa-spin]="loadingSig"></i>
                      {{ loadingSig ? 'Traitement IA...' : 'Traiter et Sauvegarder' }}
                    </button>
                  </div>
                </div>
              </div>

              <!-- User Details Info -->
              <div class="bg-indigo-900 rounded-2xl p-8 text-white shadow-indigo-lg">
                <div class="flex items-center gap-4 mb-6">
                  <div class="w-16 h-16 rounded-2xl bg-white/10 flex items-center justify-center border border-white/10">
                    <i class="fas fa-id-card text-2xl text-indigo-300"></i>
                  </div>
                  <div>
                    <h4 class="text-xl font-bold">{{ fullName }}</h4>
                    <p class="text-indigo-300 text-sm">Analyste SOC • {{ roleLabel }}</p>
                  </div>
                </div>
                <div class="grid grid-cols-2 gap-6 text-sm">
                  <div class="p-4 bg-white/5 rounded-xl border border-white/5">
                    <p class="text-indigo-300 text-xs font-bold uppercase mb-1">Nom d\\'utilisateur</p>
                    <p class="font-mono">{{ username }}</p>
                  </div>
                  <div class="p-4 bg-white/5 rounded-xl border border-white/5">
                    <p class="text-indigo-300 text-xs font-bold uppercase mb-1">Adresse Email</p>
                    <p>{{ email }}</p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </main>
    </div>
  `
})
export class ProfileComponent implements OnInit {
  username = '';
  fullName = '';
  roleLabel = '';
  email = '';
  
  passwords = { old: '', new: '', confirm: '' };
  loadingPass = false;
  
  selectedFile: File | null = null;
  signaturePreview: string | null = null;
  loadingSig = false;

  private apiUrl = environment.apiUrl;

  constructor(private http: HttpClient) {}

  ngOnInit(): void {
    this.loadUserData();
  }

  loadUserData(): void {
    this.username = localStorage.getItem('username') || '';
    const firstName = localStorage.getItem('firstName') || '';
    const lastName = localStorage.getItem('lastName') || '';
    this.fullName = `${firstName} ${lastName}`.trim() || this.username;
    this.roleLabel = localStorage.getItem('role') === 'Admin' ? 'Administrateur' : 'Analyseur';
    // Email could be stored or fetched, let's assume it's stored for now or fetch it
    this.http.get<any>(`${this.apiUrl}/profile`).subscribe({
      next: (res) => {
        this.email = res.email;
        if (res.signature_path) {
          this.signaturePreview = `${this.apiUrl}/static/${res.signature_path}`;
        }
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
        this.passwords = { old: '', new: '', confirm: '' };
        this.loadingPass = false;
      },
      error: (err) => {
        alert(err.error?.message || 'Erreur lors de la mise à jour');
        this.loadingPass = false;
      }
    });
  }

  onSignatureSelected(event: any): void {
    const file = event.target.files[0];
    if (file) {
      this.selectedFile = file;
      const reader = new FileReader();
      reader.onload = (e: any) => this.signaturePreview = e.target.result;
      reader.readAsDataURL(file);
    }
  }

  uploadSignature(): void {
    if (!this.selectedFile) return;
    this.loadingSig = true;
    const formData = new FormData();
    formData.append('signature', this.selectedFile);

    this.http.post<any>(`${this.apiUrl}/profile/upload-signature`, formData).subscribe({
      next: (res) => {
        alert('Signature traitée et sauvegardée avec succès !');
        if (res.signature_path) {
          this.signaturePreview = `${this.apiUrl}/static/${res.signature_path}?t=${Date.now()}`;
        }
        this.loadingSig = false;
        this.selectedFile = null;
      },
      error: (err) => {
        alert(err.error?.message || 'Erreur lors du traitement de la signature');
        this.loadingSig = false;
      }
    });
  }
}
