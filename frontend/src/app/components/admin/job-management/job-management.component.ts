import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { LogService, Job } from '../../../services/log.service';
import { NotificationService } from '../../../services/notification.service';
import { SidebarComponent } from '../../sidebar/sidebar.component';

@Component({
  selector: 'app-job-management',
  standalone: true,
  imports: [CommonModule, SidebarComponent],
  template: `
    <div class="flex h-screen bg-slate-100">
      <app-sidebar></app-sidebar>

      <main class="flex-1 ml-64 overflow-auto p-8">
        <header class="mb-8">
          <h2 class="text-2xl font-bold text-slate-800">Validation des Tâches Planifiées</h2>
          <p class="text-slate-500 text-sm">Approuvez ou refusez les demandes de scans automatiques des analystes</p>
        </header>

        <div class="grid grid-cols-1 gap-6">
          <div *ngFor="let job of jobs" class="bg-white rounded-xl shadow-card p-6 border-l-4"
               [class.border-amber-400]="job.status === 'pending'"
               [class.border-emerald-500]="job.status === 'active'"
               [class.border-red-500]="job.status === 'refused'">
            <div class="flex justify-between items-start">
              <div class="space-y-2">
                <div class="flex items-center gap-2">
                  <span class="text-xs font-bold uppercase px-2 py-1 rounded bg-slate-100 text-slate-600">ID: #{{ job.id }}</span>
                  <span class="text-sm font-medium text-indigo-600">Demandé par: {{ job.username }}</span>
                </div>
                <h3 class="text-lg font-bold text-slate-800">Scan SSH: {{ job.target_ip }}</h3>
                <p class="text-slate-500 text-sm"><i class="fas fa-file-alt mr-2"></i>{{ job.log_path }}</p>
                <div class="flex gap-4 text-xs text-slate-400">
                  <span><i class="fas fa-redo mr-1"></i>Fréquence: {{ job.frequency }}</span>
                  <span><i class="fas fa-calendar-alt mr-1"></i>Créé le: {{ job.created_at | date:'short' }}</span>
                </div>
              </div>

              <div class="flex flex-col items-end gap-3">
                <span [class.bg-amber-100]="job.status === 'pending'"
                      [class.text-amber-700]="job.status === 'pending'"
                      [class.bg-emerald-100]="job.status === 'active'"
                      [class.text-emerald-700]="job.status === 'active'"
                      [class.bg-red-100]="job.status === 'refused'"
                      [class.text-red-700]="job.status === 'refused'"
                      class="px-3 py-1 rounded-full text-xs font-bold uppercase">
                  {{ job.status === 'pending' ? 'En attente' : job.status === 'active' ? 'Actif' : 'Refusé' }}
                </span>

                <div *ngIf="job.status === 'pending'" class="flex gap-2 mt-2">
                  <button (click)="approveJob(job)" class="bg-emerald-600 text-white px-4 py-2 rounded-lg hover:bg-emerald-700 transition text-sm font-bold">
                    Accepter
                  </button>
                  <button (click)="refuseJob(job)" class="bg-red-600 text-white px-4 py-2 rounded-lg hover:bg-red-700 transition text-sm font-bold">
                    Refuser
                  </button>
                </div>
              </div>
            </div>
          </div>

          <div *ngIf="jobs.length === 0" class="p-20 text-center bg-white rounded-xl shadow-card text-slate-400">
            <i class="fas fa-tasks text-5xl mb-4 text-slate-200"></i>
            <p>Aucune demande de job en attente.</p>
          </div>
        </div>
      </main>
    </div>
  `
})
export class JobManagementComponent implements OnInit {
  jobs: Job[] = [];

  constructor(
    private logService: LogService,
    private notify: NotificationService
  ) {}

  ngOnInit(): void {
    this.fetchJobs();
  }

  fetchJobs(): void {
    this.logService.getAdminJobs().subscribe({
      next: (res) => this.jobs = res.jobs,
      error: (err) => this.notify.error('Erreur lors de la récupération des jobs.')
    });
  }

  async approveJob(job: Job): Promise<void> {
    const confirmed = await this.notify.confirm(
      `Approuver le job de ${job.username} pour ${job.target_ip} ?`,
      'Le job passera en statut actif.'
    );
    if (confirmed) {
      this.logService.approveAdminJob(job.id, 'approve').subscribe({
        next: () => {
          this.notify.success('Job approuvé avec succès.');
          this.fetchJobs();
        },
        error: (err) => this.notify.error(err.error?.message || 'Erreur lors de l\'approbation')
      });
    }
  }

  async refuseJob(job: Job): Promise<void> {
    const reason = await this.notify.prompt(
      `Raison du refus pour ${job.target_ip}`,
      'Indiquez le motif du refus',
      'textarea'
    );
    if (reason) {
      this.logService.approveAdminJob(job.id, 'refuse', reason).subscribe({
        next: () => {
          this.notify.warning('Job refusé.');
          this.fetchJobs();
        },
        error: (err) => this.notify.error(err.error?.message || 'Erreur lors du refus')
      });
    }
  }
}
