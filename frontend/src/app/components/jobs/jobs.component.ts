import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { SidebarComponent } from '../sidebar/sidebar.component';
import { LogService } from '../../services/log.service';
import { NotificationService } from '../../services/notification.service';

@Component({
  selector: 'app-jobs',
  standalone: true,
  imports: [CommonModule, SidebarComponent, FormsModule],
  template: `
    <div class="flex h-screen bg-slate-100">
      <app-sidebar></app-sidebar>
      
      <main class="flex-1 ml-64 overflow-auto p-8">
        <header class="mb-8 flex justify-between items-center">
          <div>
            <h2 class="text-2xl font-bold text-slate-800">Tâches planifiées</h2>
            <p class="text-slate-500 text-sm">Gérez vos analyses de logs automatisées</p>
          </div>
          <button (click)="showCreateModal = true" class="bg-indigo-600 text-white px-4 py-2 rounded-lg hover:bg-indigo-700 transition shadow-indigo">
            <i class="fas fa-plus mr-2"></i>
            Nouveau Job
          </button>
        </header>

        <!-- Jobs List -->
        <div class="bg-white rounded-xl shadow-card overflow-hidden">
          <div class="p-6 border-b border-slate-200">
            <h3 class="font-bold text-slate-800">Liste des Jobs</h3>
          </div>
          
          <div class="overflow-x-auto">
            <table class="w-full text-left text-sm">
              <thead class="bg-slate-50 text-slate-500 uppercase text-[10px] font-bold">
                <tr>
                  <th class="px-6 py-3">Serveur (IP)</th>
                  <th class="px-6 py-3">Chemin du Log</th>
                  <th class="px-6 py-3">Fréquence</th>
                  <th class="px-6 py-3">Statut</th>
                  <th class="px-6 py-3">Créé le</th>
                  <th class="px-6 py-3">Actions</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-slate-100">
                <tr *ngFor="let job of jobs" class="hover:bg-slate-50 transition">
                  <td class="px-6 py-4 font-medium text-slate-800">{{ job.target_ip }}</td>
                  <td class="px-6 py-4 font-mono text-xs text-slate-500">{{ job.log_path }}</td>
                  <td class="px-6 py-4">
                    <span class="px-2 py-1 bg-slate-100 rounded text-xs text-slate-600">{{ job.frequency }}</span>
                  </td>
                  <td class="px-6 py-4">
                    <span [class]="getStatusClass(job.status)">{{ job.status }}</span>
                  </td>
                  <td class="px-6 py-4 text-slate-500">{{ formatDate(job.created_at) }}</td>
                  <td class="px-6 py-4">
                    <button (click)="deleteJob(job.id)" class="text-red-500 hover:text-red-700 transition">
                      <i class="fas fa-trash"></i>
                    </button>
                  </td>
                </tr>
                <tr *ngIf="jobs.length === 0">
                  <td colspan="6" class="p-12 text-center text-slate-500">
                    <i class="fas fa-clock text-4xl mb-4 text-slate-300"></i>
                    <p>Aucune tâche planifiée pour le moment.</p>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        <!-- Create Job Modal -->
        <div *ngIf="showCreateModal" class="fixed inset-0 bg-slate-900/50 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div class="bg-white rounded-2xl shadow-2xl w-full max-w-lg overflow-hidden animate-fade-in">
            <div class="p-6 border-b border-slate-100 flex justify-between items-center bg-slate-50">
              <h3 class="font-bold text-slate-800 text-lg">Nouvelle demande de Job</h3>
              <button (click)="showCreateModal = false" class="text-slate-400 hover:text-slate-600"><i class="fas fa-times"></i></button>
            </div>
            <div class="p-6 space-y-4">
              <div class="grid grid-cols-2 gap-4">
                <div>
                  <label class="block text-xs font-bold text-slate-500 uppercase mb-1">Serveur IP</label>
                  <input type="text" [(ngModel)]="newJob.target_ip" class="w-full px-4 py-2 bg-slate-50 border border-slate-200 rounded-lg focus:ring-2 focus:ring-indigo-500 outline-none" placeholder="192.168.1.1">
                </div>
                <div>
                  <label class="block text-xs font-bold text-slate-500 uppercase mb-1">Chemin du Log</label>
                  <input type="text" [(ngModel)]="newJob.log_path" class="w-full px-4 py-2 bg-slate-50 border border-slate-200 rounded-lg focus:ring-2 focus:ring-indigo-500 outline-none" placeholder="/var/log/syslog">
                </div>
              </div>
              <div class="grid grid-cols-2 gap-4">
                <div>
                  <label class="block text-xs font-bold text-slate-500 uppercase mb-1">Utilisateur SSH</label>
                  <input type="text" [(ngModel)]="newJob.ssh_user" class="w-full px-4 py-2 bg-slate-50 border border-slate-200 rounded-lg focus:ring-2 focus:ring-indigo-500 outline-none" placeholder="root">
                </div>
                <div>
                  <label class="block text-xs font-bold text-slate-500 uppercase mb-1">Mot de passe SSH</label>
                  <input type="password" [(ngModel)]="newJob.ssh_pass" class="w-full px-4 py-2 bg-slate-50 border border-slate-200 rounded-lg focus:ring-2 focus:ring-indigo-500 outline-none" placeholder="••••••••">
                </div>
              </div>
              <div>
                <label class="block text-xs font-bold text-slate-500 uppercase mb-1">Fréquence</label>
                <select [(ngModel)]="newJob.frequency" class="w-full px-4 py-2 bg-slate-50 border border-slate-200 rounded-lg focus:ring-2 focus:ring-indigo-500 outline-none">
                  <option value="hourly">Toutes les heures</option>
                  <option value="daily">Quotidien</option>
                  <option value="weekly">Hebdomadaire</option>
                </select>
              </div>
            </div>
            <div class="p-6 bg-slate-50 flex gap-3">
              <button (click)="showCreateModal = false" class="flex-1 px-4 py-2 border border-slate-200 text-slate-600 rounded-lg hover:bg-white transition">Annuler</button>
              <button (click)="createJob()" class="flex-1 px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition shadow-indigo">Soumettre</button>
            </div>
          </div>
        </div>
      </main>
    </div>
  `
})
export class JobsComponent implements OnInit {
  jobs: any[] = [];
  showCreateModal = false;
  newJob = {
    target_ip: '',
    log_path: '/var/log/syslog',
    frequency: 'daily',
    ssh_user: '',
    ssh_pass: ''
  };

  constructor(
    private logService: LogService,
    private notify: NotificationService
  ) {}

  ngOnInit(): void {
    this.fetchScheduledJobs();
  }

  fetchScheduledJobs(): void {
    this.logService.getJobs().subscribe({
      next: (data) => {
        if (data.status === 'success') {
          this.jobs = data.jobs;
        }
      },
      error: (err) => {
        console.error('Error fetching jobs:', err);
        this.notify.error('Impossible de charger la liste des jobs.');
      }
    });
  }

  createJob(): void {
    if (!this.newJob.target_ip || !this.newJob.ssh_user || !this.newJob.ssh_pass) {
      this.notify.warning('Veuillez remplir tous les champs obligatoires.');
      return;
    }

    this.logService.createJob(this.newJob).subscribe({
      next: (res: any) => {
        this.notify.success(res.message || 'Demande de job créée avec succès.');
        this.showCreateModal = false;
        this.fetchScheduledJobs();
        // Reset form
        this.newJob = { target_ip: '', log_path: '/var/log/syslog', frequency: 'daily', ssh_user: '', ssh_pass: '' };
      },
      error: (err: any) => {
        this.notify.error(err.error?.message || 'Erreur lors de la création du job.');
      }
    });
  }

  async deleteJob(id: number): Promise<void> {
    const confirmed = await this.notify.confirm(
      'Supprimer ce job ?',
      'Cette action est irréversible et arrêtera toute analyse planifiée pour ce serveur.',
      'warning'
    );

    if (confirmed) {
      this.logService.deleteJob(id).subscribe({
        next: (res) => {
          this.notify.success(res.message || 'Job supprimé avec succès.');
          this.fetchScheduledJobs();
        },
        error: (err) => this.notify.error('Erreur lors de la suppression.')
      });
    }
  }

  getStatusClass(status: string): string {
    const base = "px-2 py-1 rounded-full text-[10px] font-bold uppercase ";
    if (status === 'active') return base + "bg-emerald-100 text-emerald-700";
    if (status === 'pending') return base + "bg-amber-100 text-amber-700";
    if (status === 'refused') return base + "bg-red-100 text-red-700";
    return base + "bg-slate-100 text-slate-600";
  }

  formatDate(dateStr: string): string {
    if (!dateStr) return 'N/A';
    return new Date(dateStr).toLocaleDateString();
  }
}

