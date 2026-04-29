import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { LogService, Job } from '../../../services/log.service';
import { NotificationService } from '../../../services/notification.service';
import { SidebarComponent } from '../../sidebar/sidebar.component';

@Component({
  selector: 'app-job-management',
  standalone: true,
  imports: [CommonModule, SidebarComponent],
  templateUrl: './job-management.component.html',
  styleUrls: ['./job-management.component.css']
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
