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
  templateUrl: './jobs.component.html',
  styleUrls: ['./jobs.component.css']
})
export class JobsComponent implements OnInit {
  jobs: any[] = [];
  showCreateModal = false;
  togglingJobId: number | null = null;
  newJob = {
    target_ip: '',
    log_path: '/var/log/syslog',
    frequency: 'daily',
    custom_interval: 30,
    custom_unit: 'minutes',
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
        this.newJob = { 
          target_ip: '', 
          log_path: '/var/log/syslog', 
          frequency: 'daily', 
          custom_interval: 30,
          custom_unit: 'minutes',
          ssh_user: '', 
          ssh_pass: '' 
        };
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
    const base = "px-3 py-1.5 rounded-xl text-[9px] font-black uppercase tracking-widest border transition-all duration-300 ";
    if (status === 'active') return base + "bg-emerald-500/20 text-emerald-400 border-emerald-500/20";
    if (status === 'inactive' || status === 'pending') return base + "bg-amber-500/20 text-amber-400 border-amber-500/20";
    if (status === 'refused') return base + "bg-rose-500/20 text-rose-400 border-rose-500/20";
    return base + "bg-slate-500/20 text-slate-400 border-slate-500/20";
  }

  formatDate(dateStr: string): string {
    if (!dateStr) return 'N/A';
    return new Date(dateStr).toLocaleDateString();
  }

  toggleJob(id: number): void {
    this.togglingJobId = id;
    this.logService.toggleJob(id).subscribe({
      next: (res) => {
        this.notify.success(res.message);
        this.fetchScheduledJobs();
        this.togglingJobId = null;
      },
      error: (err) => {
        this.notify.error('Erreur lors de la modification du statut.');
        this.togglingJobId = null;
      }
    });
  }
}

